#!/usr/bin/env -S python3 -u

"""
Run tests/e2e in a GKE cluster
"""
import os
from runners import ClusterTestRunner
from clusters import GKECluster
from pre_tests import PreSystemTests
from ci_tests import NonGroovyE2e
from post_tests import PostClusterTest, FinalPost

# set required test parameters
os.environ["ORCHESTRATOR_FLAVOR"] = "k8s"

os.environ["ROX_POSTGRES_DATASTORE"] = "true"

ClusterTestRunner(
    cluster=GKECluster("nongroovy-test"),
    pre_test=PreSystemTests(),
    test=NonGroovyE2e(),
    post_test=PostClusterTest(
        check_stackrox_logs=False,
    ),
    final_post=FinalPost(
        store_qa_test_debug_logs=False,
        store_qa_spock_results=False,
    ),
).run()
