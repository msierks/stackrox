package searchbasedpolicies

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blevesearch/bleve"
	"github.com/gogo/protobuf/proto"
	gogoTypes "github.com/gogo/protobuf/types"
	deploymentIndex "github.com/stackrox/rox/central/deployment/index"
	"github.com/stackrox/rox/central/globalindex"
	imageIndex "github.com/stackrox/rox/central/image/index"
	processIndicatorDataStore "github.com/stackrox/rox/central/processindicator/datastore"
	processIndicatorIndex "github.com/stackrox/rox/central/processindicator/index"
	processIndicatorSearch "github.com/stackrox/rox/central/processindicator/search"
	processIndicatorStore "github.com/stackrox/rox/central/processindicator/store/rocksdb"
	"github.com/stackrox/rox/central/role/resources"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/image/policies"
	"github.com/stackrox/rox/pkg/defaults"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/fixtures"
	"github.com/stackrox/rox/pkg/images/types"
	policyUtils "github.com/stackrox/rox/pkg/policies"
	"github.com/stackrox/rox/pkg/protoconv"
	"github.com/stackrox/rox/pkg/readable"
	"github.com/stackrox/rox/pkg/rocksdb"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/search/blevesearch"
	"github.com/stackrox/rox/pkg/search/options/deployments"
	"github.com/stackrox/rox/pkg/searchbasedpolicies"
	"github.com/stackrox/rox/pkg/searchbasedpolicies/matcher"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stackrox/rox/pkg/testutils/rocksdbtest"
	"github.com/stackrox/rox/pkg/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/tecbot/gorocksdb"
)

func TestDefaultPolicies(t *testing.T) {
	suite.Run(t, new(DefaultPoliciesTestSuite))
}

type DefaultPoliciesTestSuite struct {
	suite.Suite

	bleveIndex bleve.Index
	db         *gorocksdb.DB
	dir        string

	testCtx  context.Context
	setupCtx context.Context
	matchCtx context.Context

	deploymentIndexer  deploymentIndex.Indexer
	deploymentSearcher search.Searcher
	imageIndexer       imageIndex.Indexer
	imageSearcher      search.Searcher
	processDataStore   processIndicatorDataStore.DataStore
	matcherBuilder     matcher.Builder

	defaultPolicies map[string]*storage.Policy

	deployments         map[string]*storage.Deployment
	images              map[string]*storage.Image
	deploymentsToImages map[string][]*storage.Image
}

func (suite *DefaultPoliciesTestSuite) SetupSuite() {
	suite.deployments = make(map[string]*storage.Deployment)
	suite.images = make(map[string]*storage.Image)
	suite.deploymentsToImages = make(map[string][]*storage.Image)

	suite.testCtx = sac.WithGlobalAccessScopeChecker(context.Background(),
		sac.AllowFixedScopes(
			sac.AccessModeScopeKeys(storage.Access_READ_ACCESS, storage.Access_READ_WRITE_ACCESS),
			sac.ResourceScopeKeys(resources.Deployment),
			sac.ResourceScopeKeys(resources.Image),
			sac.ResourceScopeKeys(resources.Indicator)))
	suite.setupCtx = sac.WithGlobalAccessScopeChecker(context.Background(),
		sac.AllowFixedScopes(
			sac.AccessModeScopeKeys(storage.Access_READ_WRITE_ACCESS),
			sac.ResourceScopeKeys(resources.Indicator)))
	suite.matchCtx = sac.WithGlobalAccessScopeChecker(context.Background(), sac.AllowAllAccessScopeChecker())
}

func (suite *DefaultPoliciesTestSuite) SetupTest() {
	envIsolator := testutils.NewEnvIsolator(suite.T())
	defer envIsolator.RestoreAll()
	envIsolator.Setenv(features.ImageLabelPolicy.EnvVar(), "true")

	var err error
	suite.bleveIndex, err = globalindex.TempInitializeIndices("")
	suite.Require().NoError(err)

	suite.db, suite.dir, err = rocksdb.NewTemp("default_policies_test.db")
	suite.Require().NoError(err)

	suite.deploymentIndexer = deploymentIndex.New(suite.bleveIndex, suite.bleveIndex)
	suite.deploymentSearcher = blevesearch.WrapUnsafeSearcherAsSearcher(suite.deploymentIndexer)

	suite.imageIndexer = imageIndex.New(suite.bleveIndex)
	suite.imageSearcher = blevesearch.WrapUnsafeSearcherAsSearcher(suite.imageIndexer)

	processStore := processIndicatorStore.New(suite.db)
	processIndexer := processIndicatorIndex.New(suite.bleveIndex)
	processSearcher := processIndicatorSearch.New(processStore, processIndexer)
	suite.processDataStore, err = processIndicatorDataStore.New(processStore, nil, processIndexer, processSearcher, nil)
	suite.Require().NoError(err)

	suite.matcherBuilder = matcher.NewBuilder(
		matcher.NewRegistry(
			suite.processDataStore,
		),
		deployments.OptionsMap,
	)

	defaults.PoliciesPath = policies.Directory()

	defaultPolicies, err := defaults.Policies()
	suite.Require().NoError(err)

	suite.defaultPolicies = make(map[string]*storage.Policy, len(defaultPolicies))
	for _, p := range defaultPolicies {
		suite.defaultPolicies[p.GetName()] = p
	}
}

func (suite *DefaultPoliciesTestSuite) TearDownTest() {
	suite.NoError(suite.bleveIndex.Close())
	rocksdbtest.TearDownRocksDB(suite.db, suite.dir)
}

func (suite *DefaultPoliciesTestSuite) TestNoDuplicatePolicyIDs() {
	ids := set.NewStringSet()
	for _, p := range suite.defaultPolicies {
		suite.True(ids.Add(p.GetId()))
	}
}

func (suite *DefaultPoliciesTestSuite) MustGetPolicy(name string) *storage.Policy {
	p, ok := suite.defaultPolicies[name]
	suite.Require().True(ok, "Policy %s not found", name)
	return p
}

func (suite *DefaultPoliciesTestSuite) mustIndexDepAndImages(deployment *storage.Deployment, images ...*storage.Image) {
	suite.NoError(suite.deploymentIndexer.AddDeployment(deployment))
	suite.NoError(suite.imageIndexer.AddImages(images))

	suite.deployments[deployment.GetId()] = deployment
	for _, i := range images {
		suite.images[i.GetId()] = i
		suite.deploymentsToImages[deployment.GetId()] = append(suite.deploymentsToImages[deployment.GetId()], i)
	}
}

func imageWithComponents(components []*storage.EmbeddedImageScanComponent) *storage.Image {
	return &storage.Image{
		Id:   uuid.NewV4().String(),
		Name: &storage.ImageName{FullName: "ASFASF"},
		Scan: &storage.ImageScan{
			Components: components,
		},
	}
}

func imageWithLayers(layers []*storage.ImageLayer) *storage.Image {
	return &storage.Image{
		Id: uuid.NewV4().String(),
		Metadata: &storage.ImageMetadata{
			V1: &storage.V1Metadata{
				Layers: layers,
			},
		},
	}
}

func deploymentWithImageAnyID(img *storage.Image) *storage.Deployment {
	return &storage.Deployment{
		Id:         uuid.NewV4().String(),
		Containers: []*storage.Container{{Image: types.ToContainerImage(img)}},
	}
}

func deploymentWithImage(id string, img *storage.Image) *storage.Deployment {
	return &storage.Deployment{
		Id:         uuid.NewV4().String(),
		Containers: []*storage.Container{{Image: types.ToContainerImage(img)}},
	}
}

func (suite *DefaultPoliciesTestSuite) imageIDFromDep(deployment *storage.Deployment) string {
	suite.Require().Len(deployment.GetContainers(), 1, "This function only supports deployments with exactly one container")
	id := deployment.GetContainers()[0].GetImage().GetId()
	suite.NotEmpty(id, "Deployment '%s' had no image id", proto.MarshalTextString(deployment))
	return id
}

func (suite *DefaultPoliciesTestSuite) mustAddIndicator(deploymentID, name, args, path string, lineage []string, uid uint32) *storage.ProcessIndicator {
	indicator := &storage.ProcessIndicator{
		Id:           uuid.NewV4().String(),
		DeploymentId: deploymentID,
		Signal: &storage.ProcessSignal{
			Name:         name,
			Args:         args,
			ExecFilePath: path,
			Time:         gogoTypes.TimestampNow(),
			Lineage:      lineage,
			Uid:          uid,
		},
	}
	err := suite.processDataStore.AddProcessIndicators(suite.setupCtx, indicator)
	suite.NoError(err)
	return indicator
}

type testCase struct {
	policyName         string
	expectedViolations map[string]searchbasedpolicies.Violations

	// If shouldNotMatch is specified (which is the case for policies that check for the absence of something), we verify that
	// it matches everything except shouldNotMatch.
	// If sampleViolationForMatched is provided, we verify that all the matches are the string provided in sampleViolationForMatched.
	shouldNotMatch            map[string]struct{}
	sampleViolationForMatched string
}

func (suite *DefaultPoliciesTestSuite) getImagesForDeployment(deployment *storage.Deployment) []*storage.Image {
	images := suite.deploymentsToImages[deployment.GetId()]
	if len(images) == 0 {
		images = make([]*storage.Image, len(deployment.GetContainers()))
		for i := range images {
			images[i] = &storage.Image{}
		}
	}
	suite.Equal(len(deployment.GetContainers()), len(images))
	return images
}

func (suite *DefaultPoliciesTestSuite) TestDefaultPolicies() {
	envIsolator := testutils.NewEnvIsolator(suite.T())
	defer envIsolator.RestoreAll()
	envIsolator.Setenv(features.ImageLabelPolicy.EnvVar(), "true")

	fixtureDep := fixtures.GetDeployment()
	fixturesImages := fixtures.DeploymentImages()

	suite.mustIndexDepAndImages(fixtureDep, fixturesImages...)

	nginx110 := &storage.Image{
		Id: "SHANGINX110",
		Name: &storage.ImageName{
			Registry: "docker.io",
			Remote:   "library/nginx",
			Tag:      "1.10",
		},
	}

	nginx110Dep := deploymentWithImage("nginx110", nginx110)
	suite.mustIndexDepAndImages(nginx110Dep, nginx110)

	oldScannedTime := time.Now().Add(-31 * 24 * time.Hour)
	oldScannedImage := &storage.Image{
		Id: "SHAOLDSCANNED",
		Scan: &storage.ImageScan{
			ScanTime: protoconv.ConvertTimeToTimestamp(oldScannedTime),
		},
	}
	oldScannedDep := deploymentWithImage("oldscanned", oldScannedImage)
	suite.mustIndexDepAndImages(oldScannedDep, oldScannedImage)

	addDockerFileImg := imageWithLayers([]*storage.ImageLayer{
		{
			Instruction: "ADD",
			Value:       "deploy.sh",
		},
		{
			Instruction: "RUN",
			Value:       "deploy.sh",
		},
	})
	addDockerFileDep := deploymentWithImageAnyID(addDockerFileImg)
	suite.mustIndexDepAndImages(addDockerFileDep, addDockerFileImg)

	imagePort22Image := imageWithLayers([]*storage.ImageLayer{
		{
			Instruction: "EXPOSE",
			Value:       "22/tcp",
		},
	})
	imagePort22Dep := deploymentWithImageAnyID(imagePort22Image)
	suite.mustIndexDepAndImages(imagePort22Dep, imagePort22Image)

	insecureCMDImage := imageWithLayers([]*storage.ImageLayer{
		{
			Instruction: "CMD",
			Value:       "do an insecure thing",
		},
	})

	insecureCMDDep := deploymentWithImageAnyID(insecureCMDImage)
	suite.mustIndexDepAndImages(insecureCMDDep, insecureCMDImage)

	runSecretsImage := imageWithLayers([]*storage.ImageLayer{
		{
			Instruction: "VOLUME",
			Value:       "/run/secrets",
		},
	})
	runSecretsDep := deploymentWithImageAnyID(runSecretsImage)
	suite.mustIndexDepAndImages(runSecretsDep, runSecretsImage)

	oldImageCreationTime := time.Now().Add(-100 * 24 * time.Hour)
	oldCreatedImage := &storage.Image{
		Id: "SHA:OLDCREATEDIMAGE",
		Metadata: &storage.ImageMetadata{
			V1: &storage.V1Metadata{
				Created: protoconv.ConvertTimeToTimestamp(oldImageCreationTime),
			},
		},
	}
	oldImageDep := deploymentWithImage("oldimagedep", oldCreatedImage)
	suite.mustIndexDepAndImages(oldImageDep, oldCreatedImage)

	apkImage := imageWithComponents([]*storage.EmbeddedImageScanComponent{
		{Name: "apk", Version: "1.2"},
		{Name: "asfa", Version: "1.5"},
	})
	apkDep := deploymentWithImageAnyID(apkImage)
	suite.mustIndexDepAndImages(apkDep, apkImage)

	curlImage := imageWithComponents([]*storage.EmbeddedImageScanComponent{
		{Name: "curl", Version: "1.3"},
		{Name: "curlwithextra", Version: "0.9"},
	})
	curlDep := deploymentWithImageAnyID(curlImage)
	suite.mustIndexDepAndImages(curlDep, curlImage)

	componentDeps := make(map[string]*storage.Deployment)
	for _, component := range []string{"apt", "dnf", "wget"} {
		img := imageWithComponents([]*storage.EmbeddedImageScanComponent{
			{Name: component},
		})
		dep := deploymentWithImageAnyID(img)
		suite.mustIndexDepAndImages(dep, img)
		componentDeps[component] = dep
	}

	heartbleedDep := &storage.Deployment{
		Id: "HEARTBLEEDDEPID",
		Containers: []*storage.Container{
			{
				SecurityContext: &storage.SecurityContext{Privileged: true},
				Image:           &storage.ContainerImage{Id: "HEARTBLEEDDEPSHA"},
			},
		},
	}
	suite.mustIndexDepAndImages(heartbleedDep, &storage.Image{
		Id: "HEARTBLEEDDEPSHA",
		Scan: &storage.ImageScan{
			Components: []*storage.EmbeddedImageScanComponent{
				{Name: "heartbleed", Version: "1.2", Vulns: []*storage.EmbeddedVulnerability{
					{Cve: "CVE-2014-0160", Link: "https://heartbleed", Cvss: 6, SetFixedBy: &storage.EmbeddedVulnerability_FixedBy{FixedBy: "v1.2"}},
				}},
			},
		},
	})

	requiredImageLabel := &storage.Deployment{
		Id: "requiredImageLabel",
		Containers: []*storage.Container{
			{
				Image: &storage.ContainerImage{Id: "requiredImageLabelImage"},
			},
		},
	}
	suite.mustIndexDepAndImages(requiredImageLabel, &storage.Image{
		Id: "requiredImageLabelImage",
		Metadata: &storage.ImageMetadata{
			V1: &storage.V1Metadata{
				Labels: map[string]string{
					"required-label": "required-value",
				},
			},
		},
	})

	shellshockImage := imageWithComponents([]*storage.EmbeddedImageScanComponent{
		{Name: "shellshock", Version: "1.2", Vulns: []*storage.EmbeddedVulnerability{
			{Cve: "CVE-2014-6271", Link: "https://shellshock", Cvss: 6},
			{Cve: "CVE-ARBITRARY", Link: "https://notshellshock"},
		}},
	})
	shellshockDep := deploymentWithImageAnyID(shellshockImage)
	suite.mustIndexDepAndImages(shellshockDep, shellshockImage)

	strutsImage := imageWithComponents([]*storage.EmbeddedImageScanComponent{
		{Name: "struts", Version: "1.2", Vulns: []*storage.EmbeddedVulnerability{
			{Cve: "CVE-2017-5638", Link: "https://struts", Cvss: 8, SetFixedBy: &storage.EmbeddedVulnerability_FixedBy{FixedBy: "v1.3"}},
		}},
		{Name: "OTHER", Version: "1.3", Vulns: []*storage.EmbeddedVulnerability{
			{Cve: "CVE-1223-451", Link: "https://cvefake"},
		}},
	})
	strutsDep := deploymentWithImageAnyID(strutsImage)
	suite.mustIndexDepAndImages(strutsDep, strutsImage)

	depWithNonSeriousVulnsImage := imageWithComponents([]*storage.EmbeddedImageScanComponent{
		{Name: "NOSERIOUS", Version: "2.3", Vulns: []*storage.EmbeddedVulnerability{
			{Cve: "CVE-1234-5678", Link: "https://abcdefgh"},
			{Cve: "CVE-5678-1234", Link: "https://lmnopqrst"},
		}},
	})
	depWithNonSeriousVulns := deploymentWithImageAnyID(depWithNonSeriousVulnsImage)
	suite.mustIndexDepAndImages(depWithNonSeriousVulns, depWithNonSeriousVulnsImage)

	dockerSockDep := &storage.Deployment{
		Id: "DOCKERSOCDEP",
		Containers: []*storage.Container{
			{Volumes: []*storage.Volume{
				{Source: "/var/run/docker.sock", Name: "DOCKERSOCK"},
				{Source: "NOTDOCKERSOCK"},
			}},
		},
	}
	suite.mustIndexDepAndImages(dockerSockDep)

	containerPort22Dep := &storage.Deployment{
		Id: "CONTAINERPORT22DEP",
		Ports: []*storage.PortConfig{
			{Protocol: "TCP", ContainerPort: 22},
			{Protocol: "UDP", ContainerPort: 4125},
		},
	}
	suite.mustIndexDepAndImages(containerPort22Dep)

	secretEnvDep := &storage.Deployment{
		Id: "SECRETENVDEP",
		Containers: []*storage.Container{
			{Config: &storage.ContainerConfig{
				Env: []*storage.ContainerConfig_EnvironmentConfig{
					{Key: "THIS_IS_SECRET_VAR", Value: "stealthmode", EnvVarSource: storage.ContainerConfig_EnvironmentConfig_RAW},
					{Key: "HOME", Value: "/home/stackrox"},
				},
			}},
		},
	}
	suite.mustIndexDepAndImages(secretEnvDep)

	secretEnvSrcUnsetDep := &storage.Deployment{
		Id: "SECRETENVSRCUNSETDEP",
		Containers: []*storage.Container{
			{Config: &storage.ContainerConfig{
				Env: []*storage.ContainerConfig_EnvironmentConfig{
					{Key: "THIS_IS_SECRET_VAR", Value: "stealthmode"},
				},
			}},
		},
	}
	suite.mustIndexDepAndImages(secretEnvSrcUnsetDep)

	secretKeyRefDep := &storage.Deployment{
		Id: "SECRETKEYREFDEP",
		Containers: []*storage.Container{
			{Config: &storage.ContainerConfig{
				Env: []*storage.ContainerConfig_EnvironmentConfig{
					{Key: "THIS_IS_SECRET_VAR", EnvVarSource: storage.ContainerConfig_EnvironmentConfig_SECRET_KEY},
					{Key: "HOME", Value: "/home/stackrox"},
				},
			}},
		},
	}
	suite.mustIndexDepAndImages(secretKeyRefDep)

	// Fake deployment that shouldn't match anything, just to make sure
	// that none of our queries will accidentally match it.
	suite.mustIndexDepAndImages(&storage.Deployment{Id: "FAKEID", Name: "FAKENAME"})

	depWithGoodEmailAnnotation := &storage.Deployment{
		Id: "GOODEMAILDEPID",
		Annotations: map[string]string{
			"email": "vv@stackrox.com",
		},
	}
	suite.mustIndexDepAndImages(depWithGoodEmailAnnotation)

	depWithOwnerAnnotation := &storage.Deployment{
		Id: "OWNERANNOTATIONDEP",
		Annotations: map[string]string{
			"owner": "IOWNTHIS",
			"blah":  "Blah",
			"email": "notavalidemail",
		},
	}
	suite.mustIndexDepAndImages(depWithOwnerAnnotation)

	depWitharbitraryAnnotations := &storage.Deployment{
		Id: "ARBITRARYANNOTATIONDEPID",
		Annotations: map[string]string{
			"emailnot": "vv@stackrox.com",
			"notemail": "vv@stackrox.com",
			"ownernot": "vv",
			"nowner":   "vv",
		},
	}
	suite.mustIndexDepAndImages(depWitharbitraryAnnotations)

	depWithBadEmailAnnotation := &storage.Deployment{
		Id: "BADEMAILDEPID",
		Annotations: map[string]string{
			"email": "NOTANEMAIL",
		},
	}
	suite.mustIndexDepAndImages(depWithBadEmailAnnotation)

	sysAdminDep := &storage.Deployment{
		Id: "SYSADMINDEPID",
		Containers: []*storage.Container{
			{
				SecurityContext: &storage.SecurityContext{
					AddCapabilities: []string{"CAP_SYS_ADMIN"},
				},
			},
		},
	}
	suite.mustIndexDepAndImages(sysAdminDep)

	depWithAllResourceLimitsRequestsSpecified := &storage.Deployment{
		Id: "ALLRESOURCESANDLIMITSDEP",
		Containers: []*storage.Container{
			{Resources: &storage.Resources{
				CpuCoresRequest: 0.1,
				CpuCoresLimit:   0.3,
				MemoryMbLimit:   100,
				MemoryMbRequest: 1251,
			}},
		},
	}
	suite.mustIndexDepAndImages(depWithAllResourceLimitsRequestsSpecified)

	depWithEnforcementBypassAnnotation := &storage.Deployment{
		Id: "ENFORCEMENTBYPASS",
		Annotations: map[string]string{
			"admission.stackrox.io/break-glass": "ticket-1234",
		},
	}
	suite.mustIndexDepAndImages(depWithEnforcementBypassAnnotation)

	hostMountDep := &storage.Deployment{
		Id: "HOSTMOUNT",
		Containers: []*storage.Container{
			{Volumes: []*storage.Volume{
				{Source: "/etc/passwd", Name: "HOSTMOUNT"},
				{Source: "/var/lib/kubelet", Name: "KUBELET"},
			}},
		},
	}
	suite.mustIndexDepAndImages(hostMountDep)

	// Index processes
	bashLineage := []string{"/bin/bash"}
	fixtureDepAptIndicator := suite.mustAddIndicator(fixtureDep.GetId(), "apt", "", "/usr/bin/apt", bashLineage, 1)
	sysAdminDepAptIndicator := suite.mustAddIndicator(sysAdminDep.GetId(), "apt", "install blah", "/usr/bin/apt", bashLineage, 1)

	kubeletIndicator := suite.mustAddIndicator(containerPort22Dep.GetId(), "curl", "https://12.13.14.15:10250", "/bin/curl", bashLineage, 1)
	kubeletIndicator2 := suite.mustAddIndicator(containerPort22Dep.GetId(), "wget", "https://heapster.kube-system/metrics", "/bin/wget", bashLineage, 1)

	nmapIndicatorfixtureDep1 := suite.mustAddIndicator(fixtureDep.GetId(), "nmap", "blah", "/usr/bin/nmap", bashLineage, 1)
	nmapIndicatorfixtureDep2 := suite.mustAddIndicator(fixtureDep.GetId(), "nmap", "blah2", "/usr/bin/nmap", bashLineage, 1)
	nmapIndicatorNginx110Dep := suite.mustAddIndicator(nginx110Dep.GetId(), "nmap", "", "/usr/bin/nmap", bashLineage, 1)

	javaLineage := []string{"/bin/bash", "/mnt/scripts/run_server.sh", "/bin/java"}
	fixtureDepJavaIndicator := suite.mustAddIndicator(fixtureDep.GetId(), "/bin/bash", "-attack", "/bin/bash", javaLineage, 0)

	deploymentTestCases := []testCase{
		{
			policyName: "Images with no scans",
			shouldNotMatch: map[string]struct{}{
				fixtureDep.GetId():    {},
				oldScannedDep.GetId(): {},
			},
			sampleViolationForMatched: "Image has not been scanned",
		},
		{
			policyName: "Latest tag",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				fixtureDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Image tag 'latest' matched latest",
					},
				},
				},
			},
		},
		{
			policyName: "DockerHub NGINX 1.10",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				fixtureDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Image tag '1.10' matched 1.10",
					},
					{
						Message: "Image registry 'docker.io' matched docker.io",
					},
					{
						Message: "Image remote 'library/nginx' matched nginx",
					},
				},
				},
				nginx110Dep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Image tag '1.10' matched 1.10",
					},
					{
						Message: "Image registry 'docker.io' matched docker.io",
					},
					{
						Message: "Image remote 'library/nginx' matched nginx",
					},
				},
				},
			},
		},
		{
			policyName: "Alpine Linux Package Manager (apk) in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				apkDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Component name 'apk' matched apk",
					},
				},
				},
			},
		},
		{
			policyName: "Ubuntu Package Manager in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				componentDeps["apt"].GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Component name 'apt' matched apt|dpkg",
					},
				},
				},
			},
		},
		{
			policyName: "Curl in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				curlDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Component name 'curl' matched curl",
					},
				},
				},
			},
		},
		{
			policyName: "Red Hat Package Manager in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				componentDeps["dnf"].GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Component name 'dnf' matched rpm|dnf|yum",
					},
				},
				},
			},
		},
		{
			policyName: "Wget in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				componentDeps["wget"].GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Component name 'wget' matched wget",
					},
				},
				},
			},
		},
		{
			policyName: "Mount Docker Socket",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				dockerSockDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Volume source '/var/run/docker.sock' matched /var/run/docker.sock",
					},
				},
				},
			},
		},
		{
			policyName: "90-Day Image Age",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				oldImageDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: fmt.Sprintf("Time of image creation '%s' was more than 90 days ago", readable.Time(oldImageCreationTime)),
					},
				},
				},
			},
		},
		{
			policyName: "30-Day Scan Age",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				oldScannedDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: fmt.Sprintf("Time of last scan '%s' was more than 30 days ago", readable.Time(oldScannedTime)),
					},
				},
				},
			},
		},
		{
			policyName: "Secure Shell (ssh) Port Exposed in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				imagePort22Dep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'EXPOSE 22/tcp' matches the rule EXPOSE (22/tcp|\\s+22/tcp)",
					},
				},
				},
			},
		},
		{
			policyName: "Secure Shell (ssh) Port Exposed",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				containerPort22Dep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Port '22' matched 22",
					},
					{
						Message: "Protocol 'tcp' matched tcp",
					},
				},
				},
			},
		},
		{
			policyName: "Privileged Container",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				fixtureDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Privileged container found",
					},
				},
				},
				heartbleedDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Privileged container found",
					},
				},
				},
			},
		},
		{
			policyName: "Container using read-write root filesystem",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				heartbleedDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Container using read-write root filesystem found",
					},
				},
				},
				fixtureDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Container using read-write root filesystem found",
					},
				},
				},
				sysAdminDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Container using read-write root filesystem found",
					},
				},
				},
			},
		},
		{
			policyName: "Insecure specified in CMD",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				insecureCMDDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'CMD do an insecure thing' matches the rule CMD .*insecure.*",
					},
				},
				},
			},
		},
		{
			policyName: "Improper Usage of Orchestrator Secrets Volume",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				runSecretsDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'VOLUME /run/secrets' matches the rule VOLUME /run/secrets",
					},
				},
				},
			},
		},
		{
			policyName:                "Required Label: Email",
			shouldNotMatch:            map[string]struct{}{fixtureDep.GetId(): {}},
			sampleViolationForMatched: "Required label not found (key = 'email', value = '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+')",
		},
		{
			policyName:                "Required Annotation: Email",
			shouldNotMatch:            map[string]struct{}{depWithGoodEmailAnnotation.GetId(): {}},
			sampleViolationForMatched: "Required annotation not found (key = 'email', value = '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+')",
		},
		{
			policyName:                "Required Label: Owner",
			shouldNotMatch:            map[string]struct{}{fixtureDep.GetId(): {}},
			sampleViolationForMatched: "Required label not found (key = 'owner', value = '.+')",
		},
		{
			policyName:                "Required Annotation: Owner",
			shouldNotMatch:            map[string]struct{}{depWithOwnerAnnotation.GetId(): {}},
			sampleViolationForMatched: "Required annotation not found (key = 'owner', value = '.+')",
		},
		{
			policyName: "CAP_SYS_ADMIN capability added",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				sysAdminDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "CAP_SYS_ADMIN was in the ADD CAPABILITIES list",
					},
				},
				},
			},
		},
		{
			policyName: "Shellshock: Multiple CVEs",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				shellshockDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "CVE CVE-2014-6271 matched regex 'CVE-2014-(6271|6277|6278|7169|7186|7187)'",
					},
				},
				},
				fixtureDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "CVE CVE-2014-6271 matched regex 'CVE-2014-(6271|6277|6278|7169|7186|7187)'",
					},
				},
				},
			},
		},
		{
			policyName: "Apache Struts: CVE-2017-5638",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				strutsDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "CVE CVE-2017-5638 matched regex 'CVE-2017-5638'",
					},
				},
				},
			},
		},
		{
			policyName: "Heartbleed: CVE-2014-0160",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				heartbleedDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "CVE CVE-2014-0160 matched regex 'CVE-2014-0160'",
					},
				},
				},
			},
		},
		{
			policyName: "No resource requests or limits specified",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				fixtureDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{Message: "The CPU resource limit of 0 is equal to the threshold of 0.00"},
					{Message: "The memory resource limit of 0 is equal to the threshold of 0.00"},
					{Message: "The memory resource request of 0 is equal to the threshold of 0.00"},
				},
				},
			},
		},
		{
			policyName: "Environment Variable Contains Secret",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				secretEnvDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Container Environment (key='THIS_IS_SECRET_VAR', value='stealthmode') matched environment policy (key = '.*SECRET.*|.*PASSWORD.*', value from = 'RAW')",
					},
				},
				},
			},
		},
		{
			policyName: "Secret Mounted as Environment Variable",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				secretKeyRefDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Container Environment (key='THIS_IS_SECRET_VAR', value='') matched environment policy (value from = 'SECRET_KEY')",
					},
				},
				},
			},
		},
		{
			policyName: "Fixable CVSS >= 6 and Privileged",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				heartbleedDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Found a CVSS score of 6 (greater than or equal to 6.0) (cve: CVE-2014-0160) that is fixable",
					},
					{
						Message: "Privileged container found",
					},
				},
				},
			},
		},
		{
			policyName: "Fixable CVSS >= 7",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				strutsDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Found a CVSS score of 8 (greater than or equal to 7.0) (cve: CVE-2017-5638) that is fixable",
					},
				},
				},
			},
		},
		{
			policyName: "ADD Command used instead of COPY",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				addDockerFileDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'ADD deploy.sh' matches the rule ADD .*",
					},
				},
				},
				fixtureDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'ADD FILE:blah' matches the rule ADD .*",
					},
					{
						Message: "Dockerfile Line 'ADD file:4eedf861fb567fffb2694b65ebdd58d5e371a2c28c3863f363f333cb34e5eb7b in /' matches the rule ADD .*",
					},
				},
				},
			},
		},
		{
			policyName: "nmap Execution",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				fixtureDep.GetId(): {ProcessViolation: &storage.Alert_ProcessViolation{
					Message:   "Detected executions of binary '/usr/bin/nmap' with 2 different arguments with UID '1'",
					Processes: []*storage.ProcessIndicator{nmapIndicatorfixtureDep1, nmapIndicatorfixtureDep2},
				},
				},
				nginx110Dep.GetId(): {ProcessViolation: &storage.Alert_ProcessViolation{
					Message:   "Detected execution of binary '/usr/bin/nmap' without arguments with UID '1'",
					Processes: []*storage.ProcessIndicator{nmapIndicatorNginx110Dep},
				},
				},
			},
		},
		{
			policyName: "Process Targeting Cluster Kubelet Endpoint",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				containerPort22Dep.GetId(): {ProcessViolation: &storage.Alert_ProcessViolation{
					Message:   "Detected executions of 2 binaries with 2 different arguments with UID '1'",
					Processes: []*storage.ProcessIndicator{kubeletIndicator, kubeletIndicator2},
				},
				},
			},
		},
		{
			policyName: "Ubuntu Package Manager Execution",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				fixtureDep.GetId(): {ProcessViolation: &storage.Alert_ProcessViolation{
					Message:   "Detected execution of binary '/usr/bin/apt' without arguments with UID '1'",
					Processes: []*storage.ProcessIndicator{fixtureDepAptIndicator},
				},
				},
				sysAdminDep.GetId(): {ProcessViolation: &storage.Alert_ProcessViolation{
					Message:   "Detected execution of binary '/usr/bin/apt' with arguments 'install blah' with UID '1'",
					Processes: []*storage.ProcessIndicator{sysAdminDepAptIndicator},
				},
				},
			},
		},
		{
			policyName: "Process with UID 0",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				fixtureDep.GetId(): {ProcessViolation: &storage.Alert_ProcessViolation{
					Message:   "Detected execution of binary '/bin/bash' with arguments '-attack' with UID '0'",
					Processes: []*storage.ProcessIndicator{fixtureDepJavaIndicator},
				},
				},
			},
		},
		{
			policyName: "Shell Spawned by Java Application",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				fixtureDep.GetId(): {ProcessViolation: &storage.Alert_ProcessViolation{
					Message:   "Detected execution of binary '/bin/bash' with arguments '-attack' with UID '0'",
					Processes: []*storage.ProcessIndicator{fixtureDepJavaIndicator},
				},
				},
			},
		},
		{
			policyName: "Emergency Deployment Annotation",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				depWithEnforcementBypassAnnotation.GetId(): {AlertViolations: []*storage.Alert_Violation{{
					Message: "Disallowed annotation found (key = 'admission.stackrox.io/break-glass')",
				},
				},
				},
			},
		},
		{
			policyName: "Mounting Sensitive Host Directories",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				hostMountDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{Message: "Volume source '/etc/passwd' matched (/etc/.*|/sys/.*|/dev/.*|/proc/.*|/var/.*)"},
					{Message: "Volume source '/var/lib/kubelet' matched (/etc/.*|/sys/.*|/dev/.*|/proc/.*|/var/.*)"},
				},
				},
				dockerSockDep.GetId(): {AlertViolations: []*storage.Alert_Violation{
					{Message: "Volume source '/var/run/docker.sock' matched (/etc/.*|/sys/.*|/dev/.*|/proc/.*|/var/.*)"},
				},
				},
			},
		},
	}

	for _, c := range deploymentTestCases {
		p := suite.MustGetPolicy(c.policyName)
		suite.T().Run(fmt.Sprintf("%s (on deployments)", c.policyName), func(t *testing.T) {
			m, err := suite.matcherBuilder.ForPolicy(p)
			require.NoError(t, err)

			for id, violations := range c.expectedViolations {
				// Test match one only if we aren't testing processes
				if violations.ProcessViolation == nil {
					gotFromMatchOne, err := m.MatchOne(suite.matchCtx, suite.deployments[id], suite.getImagesForDeployment(suite.deployments[id]), nil)
					require.NoError(t, err)
					// Make checks case insensitive due to differences in regex
					for _, a := range violations.AlertViolations {
						a.Message = strings.ToLower(a.Message)
					}
					for _, a := range gotFromMatchOne.AlertViolations {
						a.Message = strings.ToLower(a.Message)
					}
					assert.ElementsMatch(t, violations.AlertViolations, gotFromMatchOne.AlertViolations, "Expected violations from match one %+v don't match what we got %+v", violations, gotFromMatchOne)
					assert.Equal(t, violations.ProcessViolation, gotFromMatchOne.ProcessViolation)
				}
			}

			if len(c.shouldNotMatch) > 0 {
				for id, deployment := range suite.deployments {
					gotFromMatchOne, err := m.MatchOne(suite.matchCtx, deployment, suite.getImagesForDeployment(deployment), nil)
					require.NoError(t, err)
					matched := len(gotFromMatchOne.AlertViolations) > 0
					_, shouldNotMatch := c.shouldNotMatch[id]
					if assert.NotEqual(t, matched, shouldNotMatch, "Deployment %s violated expectation about not matching (matched: %v, should match: %v)", id, matched, !shouldNotMatch) {
						if !shouldNotMatch && c.sampleViolationForMatched != "" {
							assert.Equal(t, c.sampleViolationForMatched, gotFromMatchOne.AlertViolations[0].GetMessage())
						}
					}
				}

			}
		})
	}
	imageTestCases := []testCase{
		{
			policyName: "Latest tag",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				fixtureDep.GetContainers()[1].GetImage().GetId(): {AlertViolations: []*storage.Alert_Violation{
					{Message: "Image tag 'latest' matched latest"},
				},
				},
			},
		},
		{
			policyName: "DockerHub NGINX 1.10",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				fixtureDep.GetContainers()[0].GetImage().GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Image tag '1.10' matched 1.10",
					},
					{
						Message: "Image registry 'docker.io' matched docker.io",
					},
					{
						Message: "Image remote 'library/nginx' matched nginx",
					},
				},
				},
				suite.imageIDFromDep(nginx110Dep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Image tag '1.10' matched 1.10",
					},
					{
						Message: "Image registry 'docker.io' matched docker.io",
					},
					{
						Message: "Image remote 'library/nginx' matched nginx",
					},
				},
				},
			},
		},
		{
			policyName: "Alpine Linux Package Manager (apk) in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(apkDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Component name 'apk' matched apk",
					},
				},
				},
			},
		},
		{
			policyName: "Ubuntu Package Manager in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(componentDeps["apt"]): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Component name 'apt' matched apt|dpkg",
					},
				},
				},
			},
		},
		{
			policyName: "Curl in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(curlDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Component name 'curl' matched curl",
					},
				},
				},
			},
		},
		{
			policyName: "Red Hat Package Manager in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(componentDeps["dnf"]): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Component name 'dnf' matched rpm|dnf|yum",
					},
				},
				},
			},
		},
		{
			policyName: "Wget in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(componentDeps["wget"]): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Component name 'wget' matched wget",
					},
				},
				},
			},
		},
		{
			policyName: "90-Day Image Age",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(oldImageDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: fmt.Sprintf("Time of image creation '%s' was more than 90 days ago", readable.Time(oldImageCreationTime)),
					},
				},
				},
			},
		},
		{
			policyName: "30-Day Scan Age",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(oldScannedDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: fmt.Sprintf("Time of last scan '%s' was more than 30 days ago", readable.Time(oldScannedTime)),
					},
				},
				},
			},
		},
		{
			policyName: "Secure Shell (ssh) Port Exposed in Image",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(imagePort22Dep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'EXPOSE 22/tcp' matches the rule EXPOSE (22/tcp|\\s+22/tcp)",
					},
				},
				},
			},
		},
		{
			policyName: "Insecure specified in CMD",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(insecureCMDDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'CMD do an insecure thing' matches the rule CMD .*insecure.*",
					},
				},
				},
			},
		},
		{
			policyName: "Improper Usage of Orchestrator Secrets Volume",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(runSecretsDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'VOLUME /run/secrets' matches the rule VOLUME /run/secrets",
					},
				},
				},
			},
		},
		{
			policyName: "Images with no scans",
			shouldNotMatch: map[string]struct{}{
				fixtureDep.GetContainers()[0].GetImage().GetId(): {},
				fixtureDep.GetContainers()[1].GetImage().GetId(): {},
				suite.imageIDFromDep(oldScannedDep):              {},
			},
			sampleViolationForMatched: "Image has not been scanned",
		},
		{
			policyName: "Shellshock: Multiple CVEs",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(shellshockDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "CVE CVE-2014-6271 matched regex 'CVE-2014-(6271|6277|6278|7169|7186|7187)'",
					},
				},
				},
				fixtureDep.GetContainers()[1].GetImage().GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "CVE CVE-2014-6271 matched regex 'CVE-2014-(6271|6277|6278|7169|7186|7187)'",
					},
				},
				},
			},
		},
		{
			policyName: "Apache Struts: CVE-2017-5638",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(strutsDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "CVE CVE-2017-5638 matched regex 'CVE-2017-5638'",
					},
				},
				},
			},
		},
		{
			policyName: "Heartbleed: CVE-2014-0160",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(heartbleedDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "CVE CVE-2014-0160 matched regex 'CVE-2014-0160'",
					},
				},
				},
			},
		},
		{
			policyName: "Fixable CVSS >= 7",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(strutsDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Found a CVSS score of 8 (greater than or equal to 7.0) (cve: CVE-2017-5638) that is fixable",
					},
				},
				},
			},
		},
		{
			policyName: "ADD Command used instead of COPY",
			expectedViolations: map[string]searchbasedpolicies.Violations{
				suite.imageIDFromDep(addDockerFileDep): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'ADD deploy.sh' matches the rule ADD .*",
					},
				},
				},
				fixtureDep.GetContainers()[0].GetImage().GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'ADD FILE:blah' matches the rule ADD .*",
					},
				},
				},
				fixtureDep.GetContainers()[1].GetImage().GetId(): {AlertViolations: []*storage.Alert_Violation{
					{
						Message: "Dockerfile Line 'ADD file:4eedf861fb567fffb2694b65ebdd58d5e371a2c28c3863f363f333cb34e5eb7b in /' matches the rule ADD .*",
					},
				},
				},
			},
		},
		{
			policyName: "Required Image Label",
			shouldNotMatch: map[string]struct{}{
				"requiredImageLabelImage": {},
			},
		},
	}

	for _, c := range imageTestCases {
		p := suite.MustGetPolicy(c.policyName)
		suite.T().Run(fmt.Sprintf("%s (on images)", c.policyName), func(t *testing.T) {
			m, err := suite.matcherBuilder.ForPolicy(p)
			require.NoError(t, err)
			for id, violations := range c.expectedViolations {
				// Test match one
				gotFromMatchOne, err := m.MatchOne(suite.testCtx, nil, []*storage.Image{suite.images[id]}, nil)
				require.NoError(t, err)
				assert.ElementsMatch(t, violations.AlertViolations, gotFromMatchOne.AlertViolations, "Expected violations from match one %+v don't match what we got %+v", violations, gotFromMatchOne)
			}
		})
	}
}

func (suite *DefaultPoliciesTestSuite) TestMapPolicyMatchOne() {
	noAnnotation := &storage.Deployment{
		Id: "noAnnotation",
	}
	suite.mustIndexDepAndImages(noAnnotation)

	validAnnotation := &storage.Deployment{
		Id: "validAnnotation",
		Annotations: map[string]string{
			"email": "joseph@rules.gov",
		},
	}
	suite.mustIndexDepAndImages(validAnnotation)

	policy := suite.defaultPolicies["Required Annotation: Email"]
	m, err := suite.matcherBuilder.ForPolicy(policy)
	suite.NoError(err)

	matched, err := m.MatchOne(suite.testCtx, noAnnotation, nil, nil)
	suite.NoError(err)
	suite.Len(matched.AlertViolations, 1)

	matched, err = m.MatchOne(suite.testCtx, validAnnotation, nil, nil)
	suite.NoError(err)
	suite.Empty(matched.AlertViolations)
}

func (suite *DefaultPoliciesTestSuite) TestRuntimePolicyFieldsCompile() {
	for _, p := range suite.defaultPolicies {
		if policyUtils.AppliesAtRunTime(p) && p.GetFields().GetProcessPolicy() != nil {
			processPolicy := p.GetFields().GetProcessPolicy()
			if processPolicy.GetName() != "" {
				regexp.MustCompile(processPolicy.GetName())
			}
			if processPolicy.GetArgs() != "" {
				regexp.MustCompile(processPolicy.GetArgs())
			}
			if processPolicy.GetAncestor() != "" {
				regexp.MustCompile(processPolicy.GetAncestor())
			}
		}
	}
}

func (suite *DefaultPoliciesTestSuite) TestRequiredLabel() {
	policy := suite.MustGetPolicy("Required Image Label")

	policy.Fields.RequiredImageLabel = &storage.KeyValuePolicy{
		Key:   "org.opencontainers.image.build_number",
		Value: "27",
	}

	m, err := suite.matcherBuilder.ForPolicy(policy)
	if err != nil {
		panic(err)
	}

	image := fixtures.GetImage()
	image.Metadata.V1.Labels = map[string]string{
		"org.opencontainers.image.build_number": "28",
		"i have":                                "multiple",
	}

	violations, err := m.MatchOne(context.Background(), nil, []*storage.Image{image}, nil)
	if err != nil {
		panic(err)
	}
	suite.NotEmpty(violations.AlertViolations)
}
