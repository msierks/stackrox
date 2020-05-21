import React from 'react';
import PropTypes from 'prop-types';
import posed, { PoseGroup } from 'react-pose';

const Container = posed.div({
    enter: {
        x: 0,
        transition: { ease: 'easeIn', duration: 300 },
    },
    exit: {
        x: '100%',
        transition: { ease: 'easeOut', duration: 300 },
    },
});

const SidePanelAnimation = ({ className, condition, children }) => {
    return (
        <PoseGroup>
            {condition && [
                <Container
                    key="animation-container"
                    className={`absolute z-10 h-full top-0 right-0 w-full lg:w-9/10 ${className}`}
                >
                    {children}
                </Container>,
            ]}
        </PoseGroup>
    );
};

SidePanelAnimation.propTypes = {
    className: PropTypes.string,
    condition: PropTypes.bool.isRequired,
    children: PropTypes.element.isRequired,
};

SidePanelAnimation.defaultProps = {
    className: '',
};

export default SidePanelAnimation;
