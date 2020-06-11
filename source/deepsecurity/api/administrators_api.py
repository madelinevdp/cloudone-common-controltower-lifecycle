# coding: utf-8

"""
    Trend Micro Deep Security API

    Copyright 2018 - 2020 Trend Micro Incorporated.<br/>Get protected, stay secured, and keep informed with Trend Micro Deep Security's new RESTful API. Access system data and manage security configurations to automate your security workflows and integrate Deep Security into your CI/CD pipeline.  # noqa: E501

    OpenAPI spec version: 12.5.841
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from __future__ import absolute_import

import re  # noqa: F401

# python 2 and python 3 compatibility library
import six

from deepsecurity.api_client import ApiClient


class AdministratorsApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def create_administrator(self, administrator, api_version, **kwargs):  # noqa: E501
        """Create an Administrator  # noqa: E501

        Create a new administrator.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_administrator(administrator, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param Administrator administrator: The settings of the new administrator. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Administrator
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.create_administrator_with_http_info(administrator, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.create_administrator_with_http_info(administrator, api_version, **kwargs)  # noqa: E501
            return data

    def create_administrator_with_http_info(self, administrator, api_version, **kwargs):  # noqa: E501
        """Create an Administrator  # noqa: E501

        Create a new administrator.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_administrator_with_http_info(administrator, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param Administrator administrator: The settings of the new administrator. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Administrator
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['administrator', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method create_administrator" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'administrator' is set
        if ('administrator' not in params or
                params['administrator'] is None):
            raise ValueError("Missing the required parameter `administrator` when calling `create_administrator`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `create_administrator`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'administrator' in params:
            body_params = params['administrator']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/administrators', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Administrator',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def delete_administrator(self, administrator_id, api_version, **kwargs):  # noqa: E501
        """Delete an Administrator  # noqa: E501

        Delete an administrator by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_administrator(administrator_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int administrator_id: The ID number of the administrator to delete. (required)
        :param str api_version: The version of the api being called. (required)
        :return: None
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.delete_administrator_with_http_info(administrator_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.delete_administrator_with_http_info(administrator_id, api_version, **kwargs)  # noqa: E501
            return data

    def delete_administrator_with_http_info(self, administrator_id, api_version, **kwargs):  # noqa: E501
        """Delete an Administrator  # noqa: E501

        Delete an administrator by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_administrator_with_http_info(administrator_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int administrator_id: The ID number of the administrator to delete. (required)
        :param str api_version: The version of the api being called. (required)
        :return: None
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['administrator_id', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method delete_administrator" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'administrator_id' is set
        if ('administrator_id' not in params or
                params['administrator_id'] is None):
            raise ValueError("Missing the required parameter `administrator_id` when calling `delete_administrator`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `delete_administrator`")  # noqa: E501

        if 'administrator_id' in params and not re.search('\\d+', str(params['administrator_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `administrator_id` when calling `delete_administrator`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'administrator_id' in params:
            path_params['administratorID'] = params['administrator_id']  # noqa: E501

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/administrators/{administratorID}', 'DELETE',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type=None,  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def describe_administrator(self, administrator_id, api_version, **kwargs):  # noqa: E501
        """Describe an Administrator  # noqa: E501

        Describe an administrator by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.describe_administrator(administrator_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int administrator_id: The ID number of the administrator to describe. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Administrator
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.describe_administrator_with_http_info(administrator_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.describe_administrator_with_http_info(administrator_id, api_version, **kwargs)  # noqa: E501
            return data

    def describe_administrator_with_http_info(self, administrator_id, api_version, **kwargs):  # noqa: E501
        """Describe an Administrator  # noqa: E501

        Describe an administrator by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.describe_administrator_with_http_info(administrator_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int administrator_id: The ID number of the administrator to describe. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Administrator
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['administrator_id', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method describe_administrator" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'administrator_id' is set
        if ('administrator_id' not in params or
                params['administrator_id'] is None):
            raise ValueError("Missing the required parameter `administrator_id` when calling `describe_administrator`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `describe_administrator`")  # noqa: E501

        if 'administrator_id' in params and not re.search('\\d+', str(params['administrator_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `administrator_id` when calling `describe_administrator`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'administrator_id' in params:
            path_params['administratorID'] = params['administrator_id']  # noqa: E501

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/administrators/{administratorID}', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Administrator',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def list_administrators(self, api_version, **kwargs):  # noqa: E501
        """List Administrators  # noqa: E501

        Lists all administrators.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_administrators(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :return: Administrators
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.list_administrators_with_http_info(api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.list_administrators_with_http_info(api_version, **kwargs)  # noqa: E501
            return data

    def list_administrators_with_http_info(self, api_version, **kwargs):  # noqa: E501
        """List Administrators  # noqa: E501

        Lists all administrators.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_administrators_with_http_info(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :return: Administrators
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method list_administrators" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `list_administrators`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/administrators', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Administrators',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def modify_administrator(self, administrator_id, administrator, api_version, **kwargs):  # noqa: E501
        """Modify an Administrator  # noqa: E501

        Modify an administrator by ID. Any unset elements will be left unchanged.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.modify_administrator(administrator_id, administrator, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int administrator_id: The ID number of the administrator to modify. (required)
        :param Administrator administrator: The settings of the administrator to modify. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Administrator
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.modify_administrator_with_http_info(administrator_id, administrator, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.modify_administrator_with_http_info(administrator_id, administrator, api_version, **kwargs)  # noqa: E501
            return data

    def modify_administrator_with_http_info(self, administrator_id, administrator, api_version, **kwargs):  # noqa: E501
        """Modify an Administrator  # noqa: E501

        Modify an administrator by ID. Any unset elements will be left unchanged.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.modify_administrator_with_http_info(administrator_id, administrator, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int administrator_id: The ID number of the administrator to modify. (required)
        :param Administrator administrator: The settings of the administrator to modify. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Administrator
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['administrator_id', 'administrator', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method modify_administrator" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'administrator_id' is set
        if ('administrator_id' not in params or
                params['administrator_id'] is None):
            raise ValueError("Missing the required parameter `administrator_id` when calling `modify_administrator`")  # noqa: E501
        # verify the required parameter 'administrator' is set
        if ('administrator' not in params or
                params['administrator'] is None):
            raise ValueError("Missing the required parameter `administrator` when calling `modify_administrator`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `modify_administrator`")  # noqa: E501

        if 'administrator_id' in params and not re.search('\\d+', str(params['administrator_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `administrator_id` when calling `modify_administrator`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'administrator_id' in params:
            path_params['administratorID'] = params['administrator_id']  # noqa: E501

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'administrator' in params:
            body_params = params['administrator']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/administrators/{administratorID}', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Administrator',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def search_administrators(self, api_version, **kwargs):  # noqa: E501
        """Search Administrators  # noqa: E501

        Search for administrators using optional filters.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.search_administrators(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :param SearchFilter search_filter: A collection of options used to filter the search results.
        :return: Administrators
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.search_administrators_with_http_info(api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.search_administrators_with_http_info(api_version, **kwargs)  # noqa: E501
            return data

    def search_administrators_with_http_info(self, api_version, **kwargs):  # noqa: E501
        """Search Administrators  # noqa: E501

        Search for administrators using optional filters.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.search_administrators_with_http_info(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :param SearchFilter search_filter: A collection of options used to filter the search results.
        :return: Administrators
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['api_version', 'search_filter']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method search_administrators" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `search_administrators`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'search_filter' in params:
            body_params = params['search_filter']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/administrators/search', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Administrators',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)
