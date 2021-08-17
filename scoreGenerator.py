import sys
import boto3
import json

def get_standards_status(clientSh):
    securityHubFindings = clientSh.get_findings(MaxResults=100)
    standardsDict = {}
    # loop for pagination
    while len(securityHubFindings)>0:
        if 'NextToken' in securityHubFindings:
            nextToken = securityHubFindings['NextToken']
            findings = securityHubFindings['Findings']
            securityHubFindings = clientSh.get_findings(
                MaxResults=100, NextToken=nextToken)
            for finding in findings:
                standardsDict = build_standards_dict(finding, standardsDict)  # logic to build dictionary
        else:
            break  # none left then end
    return standardsDict

def build_standards_dict(finding, standardsDict):
    if any(x in json.dumps(finding) for x in ['Compliance', 'ProductFields']):
        if 'Compliance' in finding:
            status = finding['Compliance']['Status']
            prodField = finding['ProductFields']
            if (finding['RecordState'] == 'ACTIVE' and finding['Workflow']['Status'] != 'SUPPRESSED'):  # ignore disabled controls and suppressed findings
                control = None
                # get values, json differnt for controls...
                if 'StandardsArn' in prodField:  # for aws fun
                    control = prodField['StandardsArn']
                    rule = prodField['ControlId']
                elif 'StandardsGuideArn' in prodField:  # for cis fun
                    control = prodField['StandardsGuideArn']
                    rule = prodField['RuleId']
                #ignore custom findings
                if control is not None:
                    controlName = control.split('/')[1]  # get readable name from arn
                    if controlName not in standardsDict:
                        standardsDict[controlName] = {rule: status} # add new in
                    elif not (rule in standardsDict[controlName] and (status == 'PASSED')):  # no need to update if passed
                        standardsDict[controlName][rule] = status
    return standardsDict

def generateScore(standardsDict):
    resultDict = {}
    for control in standardsDict:
        passCheck = 0
        totalControls = len(standardsDict[control])
        passCheck = len({test for test in standardsDict[control] if standardsDict[control][test] == 'PASSED'})

        # generate score
        score = round(passCheck/totalControls * 100)  # generate score
        resultDict[control] = {"Score": score} #build dictionary
    return resultDict

def main(argv):
    # Pull the profile from the parameters passed in.
    profile = argv[1]

    #create boto securityhub client
    client = (boto3.session.Session(profile_name=profile)).client('securityhub')

    scores = generateScore(get_standards_status(client))
    print(scores)

if __name__ == '__main__':
    main(sys.argv)
