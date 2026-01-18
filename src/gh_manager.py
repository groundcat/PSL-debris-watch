
import logging
from github import Github, Auth
from github.GithubException import UnknownObjectException

logger = logging.getLogger(__name__)

class GHManager:
    def __init__(self, token, repo_name):
        auth = Auth.Token(token)
        self.g = Github(auth=auth)
        self.repo = self.g.get_repo(repo_name)
        self.issues_by_title = {} # Cache
        self._load_issues()

    def _load_issues(self):
        """Preload open issues to minimize API calls."""
        logger.info("Loading existing issues...")
        open_issues = self.repo.get_issues(state='open')
        for issue in open_issues:
            self.issues_by_title[issue.title] = issue

    def create_or_update_issue(self, title, body, tag_to_add, extra_labels=None):
        """Create issue if not exists, or add tag if exists."""
        if extra_labels is None:
            extra_labels = []

        issue = self.issues_by_title.get(title)
        
        # We want to ensure tag_to_add AND extra_labels are present
        labels_to_ensure = [tag_to_add] + extra_labels

        if not issue:
            # Create new
            logger.info(f"Creating new issue for {title} with tags {labels_to_ensure}")
            new_issue = self.repo.create_issue(
                title=title,
                body=body,
                labels=labels_to_ensure
            )
            self.issues_by_title[title] = new_issue
        else:
            # Update existing
            current_labels = [l.name for l in issue.labels]
            for label in labels_to_ensure:
                if label not in current_labels:
                    logger.info(f"Adding tag {label} to existsing issue {title}")
                    issue.add_to_labels(label)

    def remove_tag_and_check_close(self, title, tag_to_remove):
        """Remove tag. If no managed tags left, close issue."""
        issue = self.issues_by_title.get(title)
        if not issue:
            return

        current_labels = [l.name for l in issue.labels]
        if tag_to_remove in current_labels:
            logger.info(f"Removing tag {tag_to_remove} from issue {title}")
            issue.remove_from_labels(tag_to_remove)
            
            # Re-fetch labels after removal.
            # PyGithub object might not update immediately, blindly trust list manipulation locally.
            remaining = [l for l in current_labels if l != tag_to_remove]
            
            # If valid management tags are empty, close it.
            MANAGED_TAGS = [
                "domain expired", "registry hold", "new registration",
                "nxdomain error", "servfail error", "_psl txt lost"
            ]
            
            remaining_managed = [l for l in remaining if l in MANAGED_TAGS]
            
            if not remaining_managed:
                logger.info(f"No managed tags left for {title}, closing issue.")
                issue.edit(state='closed')
                # Remove from cache to avoid confusion if re-opened in same run (unlikely)
                del self.issues_by_title[title]

    def ensure_body_up_to_date(self, title, new_body):
        pass
