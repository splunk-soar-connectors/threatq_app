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


def get_ctx_result(result):

    ctx_result = {}
    param = result.get_param()
    data = result.get_data()
    status = result.get_status()

    ctx_result['param'] = param

    ctx_result['status'] = status
    if (data):
        ctx_result['data'] = data[0]

    return ctx_result


def render_related(provides, all_app_runs, context):
    context['result'] = result = {}
    result['data'] = None
    result['param_contains'] = [
        'domain', 'ip', 'email', 'url', 'hash']
    for summary, action_results in all_app_runs:
        for r in action_results:
            result['data'] = r.get_data()
    return 'related_indicators.html'


def render_indicator(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    return 'new_indicator.html'


def render_event(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    return 'new_event.html'


def render_file(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            for data in result.get_data():
                results.append({'data': data})
    return 'new_file.html'


def render_summarize(provides, all_app_runs, context):
    context['result'] = result = {}
    result['data'] = None
    result['param_contains'] = [
        'domain', 'ip', 'email', 'url', 'hash']
    for summary, action_results in all_app_runs:
        for r in action_results:
            result['data'] = r.get_data()[0]
    return 'summarize.html'


def render_adversary(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    return 'new_adversary.html'
