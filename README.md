## Security Hub Score Generator 

Please find `scoreGenerator.py`, a simple python script to generate security hub scores within your AWS account. Currently, there is no API to get this score so we have to generate it ourselves in the following way:   

- Calculating a compliance readiness score by calling GetFindings
- Aggregating by complianceStatus
- Getting a summary for each technicalControlId 
- Computing the number of passed divided by total controls.

Being about to programmatically get security hub scores can help customers who want to see at a high level how an environment can change over time or as a result to a deployment. This could be adapted to store these values in AWS parameter store to keep an audit of the Security Hub Score.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install boto3.

```bash
pip3 install boto3
```

## Usage

```python
export AWS_DEFAULT_REGION=eu-west-2

python3 scoreGenerator.py my-profile
{'cis-aws-foundations-benchmark': {'Score': 76}, 'aws-foundational-security-best-practices': {'Score': 88}}
```

Tested with Python 3.7/3.10

For use with Landing zones using a Security Hub administrator account, a 2nd parameter for other accounts in the organization can be passed to get their score:

```python
export AWS_DEFAULT_REGION=eu-west-2

python3 scoreGenerator.py my-profile 123456789012
{'cis-aws-foundations-benchmark': {'Score': 90}, 'aws-foundational-security-best-practices': {'Score': 90}}
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

