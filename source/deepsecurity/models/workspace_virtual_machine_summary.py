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

from deepsecurity.models.virtual_machine_metadata import VirtualMachineMetadata  # noqa: F401,E501


class WorkspaceVirtualMachineSummary(object):
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
        'cloud_provider': 'str',
        'account_id': 'str',
        'workspace_directory': 'str',
        'user_name': 'str',
        'workspace_id': 'str',
        'bundle_id': 'str',
        'workspace_hardware': 'str',
        'state': 'str',
        'metadata': 'list[VirtualMachineMetadata]',
        'ip_address': 'str'
    }

    attribute_map = {
        'cloud_provider': 'cloudProvider',
        'account_id': 'accountID',
        'workspace_directory': 'workspaceDirectory',
        'user_name': 'userName',
        'workspace_id': 'workspaceID',
        'bundle_id': 'bundleID',
        'workspace_hardware': 'workspaceHardware',
        'state': 'state',
        'metadata': 'metadata',
        'ip_address': 'IPAddress'
    }

    def __init__(self, cloud_provider=None, account_id=None, workspace_directory=None, user_name=None, workspace_id=None, bundle_id=None, workspace_hardware=None, state=None, metadata=None, ip_address=None):  # noqa: E501
        """WorkspaceVirtualMachineSummary - a model defined in Swagger"""  # noqa: E501

        self._cloud_provider = None
        self._account_id = None
        self._workspace_directory = None
        self._user_name = None
        self._workspace_id = None
        self._bundle_id = None
        self._workspace_hardware = None
        self._state = None
        self._metadata = None
        self._ip_address = None
        self.discriminator = None

        if cloud_provider is not None:
            self.cloud_provider = cloud_provider
        if account_id is not None:
            self.account_id = account_id
        if workspace_directory is not None:
            self.workspace_directory = workspace_directory
        if user_name is not None:
            self.user_name = user_name
        if workspace_id is not None:
            self.workspace_id = workspace_id
        if bundle_id is not None:
            self.bundle_id = bundle_id
        if workspace_hardware is not None:
            self.workspace_hardware = workspace_hardware
        if state is not None:
            self.state = state
        if metadata is not None:
            self.metadata = metadata
        if ip_address is not None:
            self.ip_address = ip_address

    @property
    def cloud_provider(self):
        """Gets the cloud_provider of this WorkspaceVirtualMachineSummary.  # noqa: E501

        Cloud provider: \"AWS\".  # noqa: E501

        :return: The cloud_provider of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._cloud_provider

    @cloud_provider.setter
    def cloud_provider(self, cloud_provider):
        """Sets the cloud_provider of this WorkspaceVirtualMachineSummary.

        Cloud provider: \"AWS\".  # noqa: E501

        :param cloud_provider: The cloud_provider of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._cloud_provider = cloud_provider

    @property
    def account_id(self):
        """Gets the account_id of this WorkspaceVirtualMachineSummary.  # noqa: E501

        Account ID. Searchable as String.  # noqa: E501

        :return: The account_id of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._account_id

    @account_id.setter
    def account_id(self, account_id):
        """Sets the account_id of this WorkspaceVirtualMachineSummary.

        Account ID. Searchable as String.  # noqa: E501

        :param account_id: The account_id of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._account_id = account_id

    @property
    def workspace_directory(self):
        """Gets the workspace_directory of this WorkspaceVirtualMachineSummary.  # noqa: E501

        Name of workspace directory.  # noqa: E501

        :return: The workspace_directory of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._workspace_directory

    @workspace_directory.setter
    def workspace_directory(self, workspace_directory):
        """Sets the workspace_directory of this WorkspaceVirtualMachineSummary.

        Name of workspace directory.  # noqa: E501

        :param workspace_directory: The workspace_directory of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._workspace_directory = workspace_directory

    @property
    def user_name(self):
        """Gets the user_name of this WorkspaceVirtualMachineSummary.  # noqa: E501

        Name of workspace owner. Searchable as String.  # noqa: E501

        :return: The user_name of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._user_name

    @user_name.setter
    def user_name(self, user_name):
        """Sets the user_name of this WorkspaceVirtualMachineSummary.

        Name of workspace owner. Searchable as String.  # noqa: E501

        :param user_name: The user_name of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._user_name = user_name

    @property
    def workspace_id(self):
        """Gets the workspace_id of this WorkspaceVirtualMachineSummary.  # noqa: E501

        Workspace ID, for example: \"ws-hlt453cld\". Searchable as String.  # noqa: E501

        :return: The workspace_id of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._workspace_id

    @workspace_id.setter
    def workspace_id(self, workspace_id):
        """Sets the workspace_id of this WorkspaceVirtualMachineSummary.

        Workspace ID, for example: \"ws-hlt453cld\". Searchable as String.  # noqa: E501

        :param workspace_id: The workspace_id of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._workspace_id = workspace_id

    @property
    def bundle_id(self):
        """Gets the bundle_id of this WorkspaceVirtualMachineSummary.  # noqa: E501

        Bundle ID, for example: \"wsb-92b9h49ds\". Searchable as String.  # noqa: E501

        :return: The bundle_id of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._bundle_id

    @bundle_id.setter
    def bundle_id(self, bundle_id):
        """Sets the bundle_id of this WorkspaceVirtualMachineSummary.

        Bundle ID, for example: \"wsb-92b9h49ds\". Searchable as String.  # noqa: E501

        :param bundle_id: The bundle_id of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._bundle_id = bundle_id

    @property
    def workspace_hardware(self):
        """Gets the workspace_hardware of this WorkspaceVirtualMachineSummary.  # noqa: E501

        Hardware description, for example: \"STANDARD\". Searchable as String.  # noqa: E501

        :return: The workspace_hardware of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._workspace_hardware

    @workspace_hardware.setter
    def workspace_hardware(self, workspace_hardware):
        """Sets the workspace_hardware of this WorkspaceVirtualMachineSummary.

        Hardware description, for example: \"STANDARD\". Searchable as String.  # noqa: E501

        :param workspace_hardware: The workspace_hardware of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._workspace_hardware = workspace_hardware

    @property
    def state(self):
        """Gets the state of this WorkspaceVirtualMachineSummary.  # noqa: E501

        Power state, for example, \"POWER ON\".  # noqa: E501

        :return: The state of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._state

    @state.setter
    def state(self, state):
        """Sets the state of this WorkspaceVirtualMachineSummary.

        Power state, for example, \"POWER ON\".  # noqa: E501

        :param state: The state of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._state = state

    @property
    def metadata(self):
        """Gets the metadata of this WorkspaceVirtualMachineSummary.  # noqa: E501

        List of name/value metadata pairs.  # noqa: E501

        :return: The metadata of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :rtype: list[VirtualMachineMetadata]
        """
        return self._metadata

    @metadata.setter
    def metadata(self, metadata):
        """Sets the metadata of this WorkspaceVirtualMachineSummary.

        List of name/value metadata pairs.  # noqa: E501

        :param metadata: The metadata of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :type: list[VirtualMachineMetadata]
        """

        self._metadata = metadata

    @property
    def ip_address(self):
        """Gets the ip_address of this WorkspaceVirtualMachineSummary.  # noqa: E501


        :return: The ip_address of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._ip_address

    @ip_address.setter
    def ip_address(self, ip_address):
        """Sets the ip_address of this WorkspaceVirtualMachineSummary.


        :param ip_address: The ip_address of this WorkspaceVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._ip_address = ip_address

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
        if issubclass(WorkspaceVirtualMachineSummary, dict):
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
        if not isinstance(other, WorkspaceVirtualMachineSummary):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

