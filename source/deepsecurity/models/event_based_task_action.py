# coding: utf-8

"""
    Trend Micro Deep Security API

    Copyright 2018 - 2020 Trend Micro Incorporated.<br/>Get protected, stay secured, and keep informed with Trend Micro Deep Security's new RESTful API. Access system data and manage security configurations to automate your security workflows and integrate Deep Security into your CI/CD pipeline.  # noqa: E501

    OpenAPI spec version: 12.5.841
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class EventBasedTaskAction(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'type': 'str',
        'parameter_value': 'int'
    }

    attribute_map = {
        'type': 'type',
        'parameter_value': 'parameterValue'
    }

    def __init__(self, type=None, parameter_value=None):  # noqa: E501
        """EventBasedTaskAction - a model defined in Swagger"""  # noqa: E501

        self._type = None
        self._parameter_value = None
        self.discriminator = None

        if type is not None:
            self.type = type
        if parameter_value is not None:
            self.parameter_value = parameter_value

    @property
    def type(self):
        """Gets the type of this EventBasedTaskAction.  # noqa: E501

        Type of action taken by the event based task.  # noqa: E501

        :return: The type of this EventBasedTaskAction.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this EventBasedTaskAction.

        Type of action taken by the event based task.  # noqa: E501

        :param type: The type of this EventBasedTaskAction.  # noqa: E501
        :type: str
        """
        allowed_values = ["activate", "assign-policy", "assign-relay", "assign-group", "deactivate"]  # noqa: E501
        if type not in allowed_values:
            raise ValueError(
                "Invalid value for `type` ({0}), must be one of {1}"  # noqa: E501
                .format(type, allowed_values)
            )

        self._type = type

    @property
    def parameter_value(self):
        """Gets the parameter_value of this EventBasedTaskAction.  # noqa: E501

        The parameter value for actions that require a parameter.  activate : activation delay in minutes  assign-policy : ID of the policy to assign  assign-relay : ID of the relay group to assign  assign-group : ID of the computer group to assign  # noqa: E501

        :return: The parameter_value of this EventBasedTaskAction.  # noqa: E501
        :rtype: int
        """
        return self._parameter_value

    @parameter_value.setter
    def parameter_value(self, parameter_value):
        """Sets the parameter_value of this EventBasedTaskAction.

        The parameter value for actions that require a parameter.  activate : activation delay in minutes  assign-policy : ID of the policy to assign  assign-relay : ID of the relay group to assign  assign-group : ID of the computer group to assign  # noqa: E501

        :param parameter_value: The parameter_value of this EventBasedTaskAction.  # noqa: E501
        :type: int
        """

        self._parameter_value = parameter_value

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(EventBasedTaskAction, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, EventBasedTaskAction):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

