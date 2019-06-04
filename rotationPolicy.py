import json
import urllib3
import os
from datetime import datetime
from smtplib import SMTP
from pprint import pformat, pprint




urllib3.disable_warnings()
http = urllib3.PoolManager()
password = os.environ.get('HARBOR_PASS')
user = 'admin'
#for testing locally, you can use your harbor user/pass.  DO NOT COMMIT WITH PERSONAL INFO
auth = urllib3.util.make_headers(basic_auth=f'{user}:{password}')
date = datetime.today()
maxVersions = 10

def emailNotify(message = None):            
    host = "example.com"
    port = 25
    from_email = "from@email"
    to_list = ["to@email"]
    connection = SMTP(host, port)
    connection.ehlo()
    connection.sendmail(from_email, to_list, message)
    connection.quit()

#Gets all Project IDs
def getProjects():
    projectIds=[]
    url = "example.com/api/projects"
    get = http.request("GET", url, headers=auth)
    proj = json.loads(get.data)
    for item in proj:
        projectIds.append(item['project_id'])
    return projectIds

#gets repo names from project Id    
def getRepos(projectIds):
    repoNames = []
    for item in projectIds:
        url = f"example.com/api/repositories?project_id={item}"
        get = http.request("GET", url, headers=auth)
        repo = json.loads(get.data)
        for rname in repo:
            repoNames.append(rname['name'])
    return(repoNames)
    
#sorts the containers/tags via their creation date
def sortRepos(repoNames):
    sortedList = {}
    for repo in repoNames:
        url = f"example.com/api/repositories/{repo}/tags"
        get = http.request("GET", url, headers=auth)
        meta = json.loads(get.data)
        sortDate = sorted(meta, key=lambda x: x['created'])
        sortedList.update({f'{repo}' : sortDate})
    return(sortedList)

#gets finds container digests to be removed, dedupes them, then gets the tags for the deletion api call
def getdeleteTags(names, sortedl):
    for name in names:
        taglist = sortedl[name]
        tagdelete = []
        repodigests = []
        for tags in taglist:
            repodigests.append(tags['digest'])
            digestdedupe = list(dict.fromkeys(repodigests))
            digestdelete = []
            if len(digestdedupe) > maxVersions:
                digestdelete = digestdedupe[:-maxVersions]
        for item in taglist:
            if item['digest'] in digestdelete:
                tagdelete.append(item['name'])
        if tagdelete != []:
            delOldTags(name, tagdelete)
            email = f"Subject: Harbor Repository Retention Policy {date}\n\nRepo {name} is over the retention policy of {maxVersions}, The Container(s): tagged {tagdelete} have been removed"
            emailNotify(message = email)
            

#sends the API call for deletion of the image tags
def delOldTags(repo, tagsToDelete):
    for item in tagsToDelete:
        url = f"example.com/api/repositories/{repo}/tags/{item}"
        http.request("DELETE", url, headers=auth)
    
Ids = getProjects()
names = getRepos(Ids)
sortedl = sortRepos(names)
getdeleteTags(names, sortedl)





