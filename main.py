import requests
import os
import time

DOWNLOADS_DIR = "downloads"
REPORTS_DIR = os.path.join(DOWNLOADS_DIR, "reports")
ATTACHMENTS_DIR = os.path.join(DOWNLOADS_DIR, "attachments")

# TODO: Consider adding visual model to analyse screenshots
ALLOWED_CONTENT_TYPES = ["text/markdown", "text/x-diff"]

QUERY = """
query {
  me {
    id
    __typename
  }
  search(
    index: CompleteHacktivityReportIndex
    query_string: "disclosed:true"
    from: 0
    size: %d
    sort: { field: "latest_disclosable_activity_at", direction: DESC }
  ) {
    __typename
    total_count
    nodes {
      __typename
      ... on HacktivityDocument {
        _id
        reporter {
          _id
          name
          username
          ...UserLinkWithMiniProfile
        }
        cve_ids
        cwe
        severity_rating
        upvoted: upvoted_by_current_user
        public
        report {
          _id
          title
          substate
          url
          disclosed_at
          report_generated_content {
            id
            hacktivity_summary
          }
          comments: activities {
            nodes {
                ...ActivityFragment
            }
          }
          __typename
        }
        votes
        program: team {
          handle
          name
          url
          _id
          currency
          ...TeamLinkWithMiniProfile
        }
        total_awarded_amount
        latest_disclosable_action
        latest_disclosable_activity_at
        submitted_at
        disclosed
        has_collaboration
        __typename
      }
    }
  }
}

fragment ActivityFragment on ActivityUnion {
    ... on ReportActivityInterface {
        message
        attachments {
            _id
            file_name
            url: expiring_url
            content_type
            file_size
            moderated
        }
    }
}

fragment UserLinkWithMiniProfile on User {
  _id
  username
}

fragment TeamLinkWithMiniProfile on Team {
  _id
  handle
  name
}
"""

def ensure_directories():
    for directory in [DOWNLOADS_DIR, REPORTS_DIR, ATTACHMENTS_DIR]:
        os.makedirs(directory, exist_ok=True)

def graphql_hacktivity(n):
    return QUERY % n

REPORTS = []

def scrape_report(report_id):
    # Check if file exists
    report_file = os.path.join(REPORTS_DIR, f"{report_id}.md")
    if os.path.exists(report_file):
        return None
    
    # If not found, fetch and save
    headers = {'Content-Type': 'application/json'}
    url = f"https://hackerone.com/reports/{report_id}.json?_={int(round(time.time() * 1000))})"
    res = requests.get(url, headers=headers)
    
    time.sleep(1)
    
    data = res.json()
    
    # Format the content as markdown
    content = f"""# {data['title']}

## Vulnerability Information
{data['vulnerability_information']}

## Summary
{' '.join(filter(None, [s.get('content') for s in data['summaries']]))}

## Report URL
{data['url']}

## Disclosed At
{data['disclosed_at']}
"""
    
    # Save the formatted content to file
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return data  # Still return JSON for processing in scrape_hackerone_reports

def scrape_hackerone_reports(count):
    ensure_directories()
    # Set the headers
    headers = {'Content-Type': 'application/json'}

    # Create the request payload
    payload = {
        'query': graphql_hacktivity(count)
    }

    response = requests.post('https://hackerone.com/graphql', json=payload, headers=headers)
    
    if response.status_code == 200:
        data = response.json()['data']
        nodes = data["search"]["nodes"]

        for node in nodes:
            print(node["_id"])
            report_data = scrape_report(node['_id'])
            if report_data is None:
                continue
              
            report = {
                "id": node["_id"],
                "title": report_data["title"],
                "vulnerability_information": report_data["vulnerability_information"],
                "summaries": " ".join(filter(None, [s.get('content') for s in report_data['summaries']])),
                "link": report_data["url"],
                "reporter": node["reporter"]["username"],
                "cve_ids": node["cve_ids"],
                "cwe": node["cwe"],
                "severity_rating": node["severity_rating"],
                "votes": node["votes"],
                "awarded_amount": str(node["total_awarded_amount"]),
                "disclosed_at": report_data["disclosed_at"],
                "state": node["report"]["substate"],
                "program": node["program"],
                "comments": format_comments(node["report"]["comments"]["nodes"])
            }
            REPORTS.append(report)
    else:
        print(f'GraphQL query failed with status code {response.status_code}')

def read_attachment(url):
    print("Reading attachment")
    # Create filename from URL
    filename = url.split('/')[-1]
    file_path = os.path.join(ATTACHMENTS_DIR, filename)
    
    # Check if already downloaded
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            content = f.read()
    else:
        # Download and save
        response = requests.get(url)
        content = response.content.decode('utf-8', errors='ignore')
        with open(file_path, 'w') as f:
            f.write(content)
    
    return f"""
    THE ATTACHMENT CONTENT:
    -----------
    {content}
    -----------
    """

        
def format_comments(comments):
    formatted_comments = []
    for comment in comments:
        object = {}
        
        if comment["message"] != None and len(str(comment["message"])) > 0:
            object["message"] = comment["message"]
        
        if comment["attachments"]:
            for i, attachment in enumerate(comment["attachments"]):
                object["attachments"] = []
                if attachment["content_type"] in ALLOWED_CONTENT_TYPES:
                  object["attachments"].insert(i, {"content": read_attachment(attachment["url"])})
                else:
                  print(f'Attachment content type not allowed: {attachment["content_type"]}')
                  print("Inserting as-is")
                  object["attachments"].insert(i, attachment)
                
        if object: 
            formatted_comments.append(object)
        
    return formatted_comments

