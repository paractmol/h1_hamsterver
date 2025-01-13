from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pathlib import Path
import requests
import time
import os

@dataclass
class Config:
    DOWNLOADS_DIR: Path = Path("downloads")
    REPORTS_DIR: Path = field(default_factory=lambda: Path("downloads/reports"))
    ATTACHMENTS_DIR: Path = field(default_factory=lambda: Path("downloads/attachments"))
    ALLOWED_CONTENT_TYPES: List[str] = field(default_factory=lambda: ["text/markdown", "text/x-diff"])
    BASE_URL: str = "https://hackerone.com"
    RATE_LIMIT_DELAY: int = 1  # seconds between requests
    QUERY: str = """
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

class HackerOneAPI:
    def __init__(self, config: Config):
        self.config = config
        self.headers = {'Content-Type': 'application/json'}
        self._ensure_directories()
    
    def _ensure_directories(self) -> None:
        for directory in [self.config.DOWNLOADS_DIR, self.config.REPORTS_DIR, self.config.ATTACHMENTS_DIR]:
            os.makedirs(directory, exist_ok=True)

    def fetch_reports(self, count: int) -> List[Dict[str, Any]]:
        payload = {'query': self._build_query(count)}
        response = requests.post(f'{self.config.BASE_URL}/graphql', 
                               json=payload, 
                               headers=self.headers)
        response.raise_for_status()
        
        data = response.json()['data']
        return data["search"]["nodes"]

    def fetch_report_details(self, report_id: str) -> Optional[Dict[str, Any]]:
        report_file = self.config.REPORTS_DIR / f"{report_id}.md"
        if report_file.exists():
            return None
        
        try:
            url = f"{self.config.BASE_URL}/reports/{report_id}.json?_={int(round(time.time() * 1000))}"
            res = requests.get(url, headers=self.headers)
            res.raise_for_status()
            
            time.sleep(self.config.RATE_LIMIT_DELAY)
            return res.json()
            
        except requests.RequestException as e:
            print(f"Error fetching report {report_id}: {e}")
            return None

    @staticmethod
    def _build_query(count: int) -> str:
        # Move the existing QUERY here as a class method
        return Config.QUERY % count  # QUERY remains as is, just moved to class level

class ReportProcessor:
    def __init__(self, config: Config):
        self.config = config
        self.reports: List[Dict[str, Any]] = []

    def process_report(self, node: Dict[str, Any], report_data: Dict[str, Any]) -> None:
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
            "comments": self.format_comments(node["report"]["comments"]["nodes"])
        }
        self.reports.append(report)

    def save_report_markdown(self, report_data: Dict[str, Any], report_id: str) -> None:
        content = f"""# {report_data['title']}

## Vulnerability Information
{report_data['vulnerability_information']}

## Summary
{' '.join(filter(None, [s.get('content') for s in report_data['summaries']]))}

## Report URL
{report_data['url']}

## Disclosed At
{report_data['disclosed_at']}
"""
        report_file = self.config.REPORTS_DIR / f"{report_id}.md"
        report_file.write_text(content, encoding='utf-8')

    def format_comments(self, comments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        formatted_comments = []
        for comment in comments:
            comment_obj = {}
            
            if comment.get("message"):
                comment_obj["message"] = comment["message"]
            
            if comment.get("attachments"):
                comment_obj["attachments"] = []
                for attachment in comment["attachments"]:
                    if attachment["content_type"] in self.config.ALLOWED_CONTENT_TYPES:
                        comment_obj["attachments"].append({
                            "content": self._read_attachment(attachment["url"])
                        })
                    else:
                        print(f'Attachment content type not allowed: {attachment["content_type"]}')
                        comment_obj["attachments"].append(attachment)
                    
            if comment_obj:
                formatted_comments.append(comment_obj)
            
        return formatted_comments

    def _read_attachment(self, url: str) -> str:
        print("Reading attachment")
        filename = Path(url).name
        file_path = self.config.ATTACHMENTS_DIR / filename
        
        try:
            if file_path.exists():
                return file_path.read_text()
            
            response = requests.get(url)
            response.raise_for_status()
            content = response.content.decode('utf-8', errors='ignore')
            file_path.write_text(content)
            return content
        except (requests.RequestException, IOError) as e:
            print(f"Error processing attachment {url}: {e}")
            return f"Error reading attachment: {str(e)}"

def main():
    config = Config()
    api = HackerOneAPI(config)
    processor = ReportProcessor(config)
    
    try:
        # Fetch reports
        nodes = api.fetch_reports(count=10)  # Example count
        
        # Process each report
        for node in nodes:
            print(f"Processing report {node['_id']}")
            report_data = api.fetch_report_details(node['_id'])
            
            if report_data:
                processor.save_report_markdown(report_data, node['_id'])
                processor.process_report(node, report_data)
                
    except Exception as e:
        print(f"Error during execution: {e}")

if __name__ == "__main__":
    main()

