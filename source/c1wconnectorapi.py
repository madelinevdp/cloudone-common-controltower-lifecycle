import deepsecurity
from deepsecurity.rest import ApiException
import logging
import os

logger = logging.getLogger()


class CloudOneConnector:
    def __init__(self, api_key):
        self.configuration = deepsecurity.Configuration()
        self.configuration.host = f'https://74u3z7zmn1.execute-api.ca-central-1.amazonaws.com/dev-mvdpxx/api'
        self.oidcProvider = '74u3z7zmn1.execute-api.ca-central-1.amazonaws.com/dev-mvdpxx'
        self.configuration.api_key['api-secret-key'] = api_key
        self.connectorClient = deepsecurity.AWSConnectorsApi(deepsecurity.ApiClient(self.configuration))
        self.apiVersion = 'v1'

    def add_connector(self, role_arn):
        try:
            params = locals()
            collection_formats = {}
            path_params = {}
            query_params = []
            header_params = {}
            header_params['api-version'] = "v1"  # noqa: E501
            form_params = []
            local_var_files = {}
            body_params = {
                'roleArn': role_arn
            }
            # HTTP header `Accept`
            header_params['Accept'] = self.api_client.select_header_accept(
                ['application/json'])  # noqa: E501
            # HTTP header `Content-Type`
            header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
                ['application/json'])  # noqa: E501
            # Authentication setting
            auth_settings = ['DefaultAuthentication']  # noqa: E501

            add_connector_response = self.connectorClient.api_client.call_api(
                'cloudaccounts/aws', "POST",
                path_params,
                query_params,
                header_params,
                body=body_params,
                post_params=form_params,
                files=local_var_files,
                response_type='AWSConnector',  # noqa: E501
                auth_settings=auth_settings,
                async_req=params.get('async_req'),
                _return_http_data_only=params.get('_return_http_data_only'),
                _preload_content=params.get('_preload_content', True),
                _request_timeout=params.get('_request_timeout'),
                collection_formats=collection_formats)
            logger.info('Connector added')
            logger.info(add_connector_response)
        except ApiException as e:
            logger.info(f"Exception when calling AWSConnectorsApi.create_aws_connector: {e}")
        except Exception as e:
            logger.info(e)

    def delete_connector(self, aws_account_id):
        try:
            headers = {
                'Api-Version': 'v1',
                'Authentication': f'ApiKey {self.configuration.api_key}'
            }
            delete_connector_response = self.connectorClient.api_client.call_api(f'cloudaccounts/aws/{aws_account_id}', method="DELETE", headers_params=headers)
            logger.info('Connector deleted')
            logger.info(delete_connector_response)
        except ApiException as e:
            logger.info(f"Exception when calling AWSConnectorsApi.delete_aws_connector: {e}")
        except Exception as e:
            logger.info(e)
