import json
import urllib3
import os
from datetime import datetime
from smtplib import SMTP
from pprint import pformat
from pprint import pprint
from jira import JIRA



urllib3.disable_warnings()
http = urllib3.PoolManager()
password = os.environ.get('HARBOR_PASS')
harborBaseUrl = 'https://example.com/api'
auth = urllib3.util.make_headers(basic_auth=f'admin:{password}')
date = datetime.today()
jirapass = os.environ.get('JIRA_PASS')
server = "https://example.atlassian.net"
username = "username"
jira = JIRA(basic_auth=(username, jirapass), options={'server':server})

# Get rpject Ids in use
def getProjects():
    projectIds=[]
    url = f"{harborBaseUrl}/projects"
    get = http.request("GET", url, headers=auth)
    proj = json.loads(get.data)
    for item in proj:
        projectIds.append(item['project_id'])
    return projectIds

# Get repo names from the project IDs    
def getRepos(projectIds):
    repoNames = []
    for item in projectIds:
        url = f"{harborBaseUrl}/repositories?project_id={item}"
        get = http.request("GET", url, headers=auth)
        repo = json.loads(get.data)
        for rname in repo:
            repoNames.append(rname['name'])
    return(repoNames)
    

# get lists on vulnerable containers for email notification usage. This is deprecated, as jira integration is the next step. Also, this has an issue that im trying to duplicte keys and thats not allowed
def getResults(repoNames):
    vulnerableContainer = {}
    mitigatedContainer = {}
    for item in repoNames:
        url = f"{harborBaseUrl}/repositories/{item}/tags"
        get = http.request("GET", url, headers=auth)
        meta = json.loads(get.data)
        for entry in meta:
            try:
                labels = entry['labels']
                if entry['scan_overview']['severity'] >= 5 and labels == []:
                    vulnerableContainer[item] = [entry['name']]
                    if entry['scan_overview']['severity'] >= 5:
                        for label in labels:
                            if label['name'] != "DoNotUse":
                                vulnerableContainer[item] = [entry['name']]
                            if label['name'] == "DoNotUse":
                                mitigatedContainer[item] = [entry['name']]
            except KeyError:
                continue
    return(vulnerableContainer, mitigatedContainer)

# Create jira issues for vulnerable containers.    
def jiraCreate(repoNames):
    for repos in repoNames:
        taglist = []
        url = f"{harborBaseUrl}/repositories/{repos}/tags"
        get = http.request("GET", url, headers=auth)
        meta = json.loads(get.data)
        for entry in meta:
            try:
                labels = entry['labels']
                if entry['scan_overview']['severity'] >= 5 and labels == [] and 'snapshot' not in repos and 'test' not in repos:
                    taglist.append({repos : entry['name']})
                elif entry['scan_overview']['severity'] >= 5 and 'snapshot' not in repos and 'test' not in repos:
                    for label in labels:
                        if label['name'] != "DoNotUse":
                            taglist.append({repos : entry['name']})
            except KeyError:
                continue
        if taglist != []:
            for items in taglist:
                for key, value in items.items():
                    sev5plus = []
                    changed = False
                    try:
                        stritems = str(key).replace('{','').replace('}', '').replace("'", "")
                        descripURL = f"{harborBaseUrl}/repositories/{key}/tags/{value}/vulnerability/details"
                        getDescrip = http.request("GET", descripURL, headers=auth)
                        metaDescrip = json.loads(getDescrip.data)
                        for descriptions in metaDescrip:
                            if descriptions['severity'] >= 5:
                                sev5plus.append(descriptions)
                        vulndescrip = ""
                        search_list = list(jira.search_issues(f'project = SECAD AND (status = backlog OR status = "To Do" OR status = "In Progress" OR status = verify) AND summary ~ "Harbor Vulnerability for {key}:{value}"'))
                        closed_search_list = list(jira.search_issues(f'project = SECAD AND (status = "Won\'t Fix" OR status = Closed OR status = Resolved) AND summary ~ "Harbor Vulnerability for {key}:{value}"'))
                        if closed_search_list != []:
                            for issues in closed_search_list:
                                existDescrip= jira.issue(issues).fields.description                            
                            CVEList = []
                            for vulns in sev5plus:
                                CVEList.append(vulns['id'])
                                for id in CVEList:
                                    if id not in existDescrip:
                                        changed = True
                                changed
                        if search_list == [] and closed_search_list == []:
                            for vulns in sev5plus:
                                vulndescrip = vulndescrip + f"Vulnerability ID: {vulns['id']}\nSeverity: {vulns['severity']}\nVulnerable Package: {vulns['package']}\nVulnerable Version: {vulns['version']}\nFixed Version: {vulns['fixedVersion']}\nLink: {vulns['link']}\n\n"
                            new_issue = jira.create_issue(project='SECAD', summary = f"Harbor Registry Vulnerability Found for {key}:{value}", description = f'The following issues are all of the found vulnerabiities of severity 5 or higher:\n\n\n {vulndescrip}', issuetype = {'name': "Story"})
                            print('new issue will be created')
                        if changed == True:
                            for vulns in sev5plus:
                                vulndescrip = vulndescrip + f"Vulnerability ID: {vulns['id']}\nSeverity: {vulns['severity']}\nVulnerable Package: {vulns['package']}\nVulnerable Version: {vulns['version']}\nFixed Version: {vulns['fixedVersion']}\nLink: {vulns['link']}\n\n"
                            new_issue = jira.create_issue(project='SECAD', summary = f"Harbor Registry Vulnerability Found for {key}:{value}", description = f'The following issues are all of the found vulnerabiities of severity 5 or higher:\n\n\n {vulndescrip}', issuetype = {'name': "Story"})
                        else:
                            pass
                    except KeyError:
                        continue
#DEPRECATED email will no longer be used, as jira tickets will be opened    
# def emailNotify(message = None):            
#     host = "bwprsmtp1.ops.about.com"
#     port = 25
#     from_email = "sysops@dotdash.com"
#     to_list = ["sysops@dotdash.com", "security@dotdash.com"]
#     connection = SMTP(host, port)
#     connection.ehlo()
#     connection.sendmail(from_email, to_list, message)
#     connection.quit()

if __name__ == "__main__":
    Ids = getProjects()
    Names = getRepos(Ids)
    # Deprecated VulnCont, DNUCont = getResults(Names)
    jiraCreate(Names)

    ####DEPRECATED IN FAVOR OF JIRA
    # DoNotUse = pformat(DNUCont)
    # Vulnerable = pformat(VulnCont)
    # 
    # if VulnCont == {} and DNUCont == {}:
    #     email = f"Subject: Harbor/Claire Scan Results for {date}\n\nThe Scan found no containers with vulnerabilities. Congrats!!"
    # if VulnCont != {} or DNUCont !={}:
    #     email = f"Subject: Harbor/Claire Scan Results for {date}\n\nThe Scan found that the following containers have a severity score of 5 or higher and have not been marked as DoNotUse. Please fix and push new containers to the registry. Once pushed, please apply the 'DoNotUse' label to the vulnerable container \n\n{Vulnerable}\n\nThe following containers have a severity score of 5 or higher, and have been labeled 'DoNotUse'\nThis means a new version has been pushed with the vulnerability fixed. Please ensure no applications are pulling this version. Once you are sure nothing is pulling this container, feel free to remove it from the repo.\n\n {DoNotUse}\n\nhttps://ue1pr1harbor.prod.aws.about.com\nThanks"
    # 
    # emailNotify(message = email)

