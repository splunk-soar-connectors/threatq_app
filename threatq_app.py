# -*- coding: utf-8 -*-
# --------------------------------------------------------------------------------------------------
# ThreatQuotient Proprietary and Confidential
# Copyright ©2016 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from ThreatQuotient, Inc.
# --------------------------------------------------------------------------------------------------

from __future__ import division
# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# ThreatQ SDK
from threatqsdk import Threatq, Indicator, Source, Event, File, Adversary

# Imports local to this App
from threatq_app_consts import *  # noqa ignore=F405

import simplejson as json
import datetime
from dateutil.parser import parse
import traceback
import os


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


# Define the App Class
class TQConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TQConnector, self).__init__()
        self.tq = None

    def _test_connectivity(self, param):

        config = self.get_config()

        # get the config
        tq_host = config.get('tq_server')
        clientid = config.get('clientid')
        username = config.get('username')
        password = config.get('password')

        trust_ssl = config['trust_ssl']

        if trust_ssl:
            if ('REQUESTS_CA_BUNDLE' in os.environ):
                del os.environ['REQUESTS_CA_BUNDLE']

        if (not tq_host):
            self.save_progress("Server not set")
            return self.get_status()

        self.save_progress("Attempting to authenticate...")

        # Progress
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, tq_host)

        try:
            Threatq(tq_host, {'clientid': clientid, 'auth': {
                'email': username, 'password': password}})
        except Exception as e:
            tb = traceback.format_exc()
            m = '{} -- {}'.format(e, tb)
            self.set_status(phantom.APP_ERROR, ERR_SERVER_CONNECTION, m)
            self.append_to_message(ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS,
                                             SUCC_CONNECTIVITY_TEST)

    def _get_tq_indicator(self, query, withp=None):
        """Wrapper to query for indicators

        Args:
            tq (obj): TQ object
            query (str): the value to query.
            withp (str): withp parameters to pass to API

        Returns:
            results (dict): Indicator or empty dict
        """
        results = self.tq.get('/api/indicators', params={
            'value': query}, withp=withp)

        return results

    def _handle_query_tq_query_attributes(self, param):
        """Query TQ and return attributes"""
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        query = param['query']

        # Query TQ
        results = self._get_tq_indicator(query, "attributes")
        if results['total'] > 0:
            # We have results
            results = results.get('data')[0]
            action_result.add_data(results)
            attributes = results['attributes']
            message = 'Found {} attributes'.format(len(attributes))
            action_result.append_to_message(message)
            action_result.update_summary({'attributes': len(attributes)})
            action_result.set_status(phantom.APP_SUCCESS, message)
        else:
            # We don't have results
            message = 'Found 0 attributes'
            action_result.append_to_message(message)
            action_result.update_summary({'attributes': 0})
            return action_result.set_status(phantom.APP_SUCCESS, NO_DATA)

        return action_result.get_status()

    def _handle_create_indicator(self, param):
        """Add Indicator in TQ"""
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        indicator = param['indicator']

        p = 'status,type'
        existing_indicator = self._get_tq_indicator(indicator, withp=p)
        if existing_indicator['total'] > 0:
            # Indicator already exists, return infos
            results = existing_indicator.get('data')[0]
            ind = Indicator(self.tq)
            ind.fill_from_api_response(results)
            data = {
                'id': ind.iid,
                'value': ind.value,
                'status': ind.statusname,
                'type': ind.typename,
                'url': ind.url(),
                'existing': True
            }
            action_result.add_data(data)
            message = 'Indicator already exists'
            action_result.append_to_message(message)
            action_result.update_summary(data)
            action_result.set_status(phantom.APP_SUCCESS, message)
        else:
            # We don't have results
            # Create Indicator
            ind = Indicator(self.tq)
            ind.set_value(indicator)
            ind.set_type(param['indicator_type'])
            ind.set_status(param['indicator_status'])
            try:
                iid = ind.upload(sources=Source('Phantom'))
                data = {
                    'id': ind.iid,
                    'value': ind.value,
                    'status': ind.statusname,
                    'type': ind.typename,
                    'url': ind.url(),
                    'existing': False
                }
                action_result.add_data(data)
                message = 'Created indicator: {}'.format(iid)
                action_result.append_to_message(message)
                action_result.update_summary(data)
                action_result.set_status(phantom.APP_SUCCESS, message)
            except Exception as e:
                # Error creating indicator
                message = 'Unable to create indicator'
                action_result.append_to_message(message)
                action_result.set_status(phantom.APP_ERROR, ERR_QUERY, e)

        return action_result.get_status()

    def _handle_get_related_indicators(self, param):
        """Add Indicator in TQ"""
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        indicator = param['query']

        existing_indicator = self._get_tq_indicator(indicator)
        if existing_indicator['total'] > 0:
            # Indicator already exists, let's check related indicators
            results = existing_indicator.get('data')[0]
            ind = Indicator(self.tq)
            ind.fill_from_api_response(results)
            # not using built-in related_indicators method
            p = 'indicators.type,indicators.status'
            rel_inds = self.tq.get(
                '/api/indicators/{}'.format(ind.iid), withp=p)
            related_indicators = rel_inds.get('data').get('indicators')
            # related_indicators = ind.get_related_indicators()
            if not related_indicators:
                # We don't have any related indicators so return NO_DATA
                message = 'No related indicators found'
                action_result.append_to_message(message)
                action_result.update_summary({'related_indicators': 0})
                action_result.set_status(phantom.APP_SUCCESS, NO_DATA)
            else:
                # We have some related indicators
                for raw_ind in related_indicators:
                    ind = Indicator(self.tq)
                    ind.fill_from_api_response(raw_ind)
                    data = {
                        'id': ind.iid,
                        'value': ind.value,
                        'status': ind.statusname,
                        'type': ind.typename,
                        'url': ind.url()
                    }
                    action_result.add_data(data)
                message = 'Found {} related indicators'.format(len(data))
                action_result.append_to_message(message)
                action_result.update_summary({'related_indicators': len(related_indicators)})
                action_result.set_status(phantom.APP_SUCCESS, message)
        else:
            # We don't have results for the query
            message = 'Indicator not found in TQ'
            action_result.append_to_message(message)
            action_result.set_status(phantom.APP_SUCCESS, NO_DATA)

        return action_result.get_status()

    def _handle_link_indicator(self, param):
        """Links an indicator with another"""
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # Determine if indicator 1 is valid indicator
        indicator_1 = param['indicator_1']
        existing_indicator_1 = self._get_tq_indicator(indicator_1)
        if existing_indicator_1['total'] == 0:
            # indicator_1 not a valid indicator
            message = 'Indicator {} not found in TQ'.format(indicator_1)
            action_result.append_to_message(message)
            action_result.update_summary({'success': False})
            action_result.set_status(phantom.APP_ERROR, message)
            return self.get_status()
        # Determine if param 2 is a valid indicator
        indicator_2 = param['indicator_2']
        existing_indicator_2 = self._get_tq_indicator(indicator_2)
        if existing_indicator_2['total'] == 0:
            # indicator_2 not a valid indicator
            message = 'Indicator {} not found in TQ'.format(indicator_2)
            action_result.append_to_message(message)
            action_result.update_summary({'success': False})
            action_result.set_status(phantom.APP_ERROR, message)
            return self.get_status()
        # Link indicator_2 to indicator_1
        try:
            iid_1 = existing_indicator_1.get('data')[0]['id']
            iid_2 = existing_indicator_2.get('data')[0]['id']
            data = [{'id': iid_2}]
            self.tq.post(
                '/api/indicators/{}/indicators'.format(iid_1), data=data)
            message = 'Indicator {} linked to {}'.format(
                indicator_1, indicator_2)
            action_result.append_to_message(message)
            action_result.update_summary({'success': True})
            action_result.set_status(phantom.APP_SUCCESS, message)
        except Exception as e:
            # Some Error
            action_result.set_status(
                phantom.APP_ERROR, ERR_SERVER_CONNECTION, e)
        return action_result.get_status()

    def _handle_create_event(self, param):
        """Create info based on container"""
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # Grab current container info. X and Z are placeholder vars
        x, container_info, z = self.get_container_info()
        event_name = container_info['name']
        event_source = Source('Phantom')
        # event_type = container_info['label'].capitalize()
        event_type = 'Incident'  # hard-coded for now
        if not container_info['description']:
            event_desc = 'Event created from Phantom'
        else:
            event_desc = container_info['description']
        start_time = parse(container_info['start_time'])
        event_time = datetime.datetime.strftime(
            start_time, '%Y-%m-%d %H:%M:%S')
        # Event Attributes
        severity = container_info['severity']
        sensitivity = container_info['sensitivity']
        due_time = parse(container_info['due_time'])
        due_time = datetime.datetime.strftime(due_time, '%Y-%m-%d %H:%M:%S')

        event = Event(self.tq)
        event.set_title(event_name)
        event.set_desc(event_desc)
        event.set_type(event_type)
        event.set_date(event_time)
        try:
            eid = event.upload(sources=event_source)
            event.add_attribute('Severity', severity, sources=event_source)
            event.add_attribute('Sensitivity', sensitivity,
                                sources=event_source)
            event.add_attribute('Due Time', due_time, sources=event_source)
            message = 'Event {} created'.format(eid)
            action_result.append_to_message(message)
            url = '{}/events/{}/details'.format(self.tq.threatq_host, eid)
            data = {
                'eid': eid,
                'url': url,
                'title': event_name
            }
            action_result.add_data(data)
            action_result.update_summary(data)
            action_result.set_status(phantom.APP_SUCCESS, message)
        except Exception as e:
            # Error creating event
            message = 'Unable to create event'
            action_result.append_to_message(message)
            action_result.set_status(phantom.APP_ERROR, ERR_QUERY, e)

        return action_result.get_status()

    def _upload_cb(self, monitor):
        s = '{:.0%}'.format(monitor.bytes_read / monitor.len)
        self.send_progress(s)

    def _handle_upload_files(self, param):
        """Upload file in the vault to TQ"""
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # Check to see if we have any files in the first place
        vault_id = param['vault_id']
        v_file = Vault.get_file_info(vault_id=vault_id)
        if v_file:
            v_file = v_file[0]
            file_name = v_file['name']
            file_path = v_file['path']
            file_source = Source('Phantom')
            # file_type = config['file_type']  # should this be set?
            file_type = 'Phantom Vault File'
            tq_file = File(self.tq)
            tq_file.name = file_name
            tq_file.path = file_path
            tq_file.ftype = file_type
            try:
                tq_file.chunk_upload(sources=file_source, callback=self._upload_cb)
                fid = tq_file.fid
                url = '{}/files/{}/details'.format(self.tq.threatq_host, fid)
                data = {
                    'fid': fid,
                    'url': url,
                    'file_name': file_name
                }
                action_result.add_data(data)
                action_result.update_summary(data)
            except Exception as e:
                # Issue uploading file
                message = 'Error uploading file: {}'.format(file_name)
                action_result.set_status(
                    phantom.APP_ERROR, message, e)
                return action_result.get_status()
            action_result.set_status(
                phantom.APP_SUCCESS, 'Successfully uploaded files')
            return action_result.get_status()
        else:
            # Invalid Vault ID
            message = 'Invalid Vault ID: {}'.format(vault_id)
            action_result.set_status(
                phantom.APP_ERROR, message, e)
            return action_result.get_status()

    def _handle_summarize(self, param):
        """Query TQ and return attributes"""
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        query = param['query']

        # Query TQ
        p = ['attributes', 'indicators.type',
             'indicators.status', 'status', 'type', 'adversaries.sources']
        p = ','.join(p)
        results = self._get_tq_indicator(query, p)
        if results['total'] > 0:
            # We have results
            results = results.get('data')[0]
            attributes = results['attributes']
            indicators = results['indicators']
            status = results['status']
            itype = results['type']
            adversaries = results['adversaries']
            for adversary in adversaries:
                adv_source = None
                if adversary['sources']:
                    adv_source = adversary['sources'][0].get('name')
                adversary['source_name'] = adv_source
                aid = adversary['id']
                url = '{}/adversaries/{}/details'.format(
                    self.tq.threatq_host, aid)
                adversary['url'] = url
            data = {
                'value': results['value'],
                'attributes': attributes,
                'indicators': indicators,
                'status': status,
                'type': itype,
                'adversaries': adversaries
            }
            action_result.add_data(data)
            action_result.update_summary(data)
            action_result.set_status(phantom.APP_SUCCESS, SUCC_QUERY)
        else:
            # We don't have results
            message = 'Indicator Not Found'
            action_result.append_to_message(message)
            return action_result.set_status(phantom.APP_SUCCESS, NO_DATA)

        return action_result.get_status()

    def _handle_update_status(self, param):
        """Update the status of an indicator"""
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        indicator = param['indicator']
        new_status = param['new_status']

        results = self._get_tq_indicator(indicator)
        if results['total'] > 0:
            # We have results
            results = results.get('data')[0]
            ind = Indicator(self.tq)
            ind.fill_from_api_response(results)
            try:
                iid = ind.iid
                data = {'status': new_status}
                self.tq.put('/api/indicators/{}'.format(iid), data=data)
                action_result.add_data(data)
                action_result.set_status(phantom.APP_SUCCESS, SUCC_QUERY)
                action_result.update_summary(data)
                return action_result.get_status()
            except Exception as e:
                # Issue changing status
                message = 'Error changing status'
                action_result.set_status(
                    phantom.APP_ERROR, message, e)
                return action_result.get_status()
        else:
            # We don't have results
            message = 'Indicator Not Found'
            action_result.append_to_message(message)
            return action_result.set_status(phantom.APP_SUCCESS, NO_DATA)

    def _handle_create_adversary(self, param):
        """Create an adversary in ThreatQ"""
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        adversary_name = param['adversary_name']
        query = {'name': adversary_name}
        results = self.tq.get('/api/adversaries', params=query)
        if results['total'] > 0:
            # Adversary already exists with adversary_name
            adv = Adversary(self.tq)
            adv.fill_from_api_response(results.get('data')[0])
            url = '{}/adversaries/{}/details'.format(
                self.tq.threatq_host, adv.aid)
            data = {
                'aid': adv.aid,
                'name': adv.name,
                'url': url,
                'existing': True
            }
            action_result.add_data(data)
            message = 'Adversary already exists'
            action_result.append_to_message(message)
            action_result.update_summary(data)
            action_result.set_status(phantom.APP_SUCCESS, message)
        else:
            # Create the adversary
            published_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            description = None
            source = Source('Phantom')

            adv = Adversary(self.tq)
            adv.name = adversary_name
            adv.description = description
            adv.published_at = published_at
            try:
                adv.upload(sources=source)
                message = 'Aversary {} created'.format(adv.aid)
                action_result.append_to_message(message)
                url = '{}/adversaries/{}/details'.format(
                    self.tq.threatq_host, adv.aid)
                data = {
                    'aid': adv.aid,
                    'url': url,
                    'name': adversary_name,
                    'existing': False
                }
                action_result.add_data(data)
                action_result.update_summary(data)
                action_result.set_status(phantom.APP_SUCCESS, message)
            except Exception as e:
                # Error creating adversary
                message = 'Unable to create adversary'
                action_result.append_to_message(message)
                action_result.set_status(phantom.APP_ERROR, message, e)

            return action_result.get_status()

    def handle_action(self, param):
        """Logic to handle context menu choice"""
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        # Check if we are testing connectivity through the UI
        if (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        else:
            # We are doing some other action, so validate TQ connection before
            # Get the config
            config = self.get_config()
            tq_host = config.get('tq_server')
            clientid = config.get('clientid')
            username = config.get('username')
            password = config.get('password')
            trust_ssl = config['trust_ssl']

            if trust_ssl:
                if ('REQUESTS_CA_BUNDLE' in os.environ):
                    del os.environ['REQUESTS_CA_BUNDLE']
            try:
                # Check login
                tq = Threatq(tq_host, {'clientid': clientid, 'auth': {
                             'email': username, 'password': password}})
                self.tq = tq
            except Exception as e:
                # We can't login
                return self.set_status(
                    phantom.APP_ERROR, ERR_SERVER_CONNECTION, e)

            if (action_id == 'query_tq_attributes'):
                ret_val = self._handle_query_tq_query_attributes(param)
            elif (action_id == 'add_indicator'):
                ret_val = self._handle_create_indicator(param)
            elif (action_id == 'get_related_indicators'):
                ret_val = self._handle_get_related_indicators(param)
            elif (action_id == 'link_indicators'):
                ret_val = self._handle_link_indicator(param)
            elif (action_id == 'create_event'):
                ret_val = self._handle_create_event(param)
            elif (action_id == 'upload_files'):
                ret_val = self._handle_upload_files(param)
            elif ('summarize' in action_id):
                ret_val = self._handle_summarize(param)
            elif (action_id == 'change_status'):
                ret_val = self._handle_update_status(param)
            elif (action_id == 'create_adversary'):
                ret_val = self._handle_create_adversary(param)

        return ret_val

if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TQConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
