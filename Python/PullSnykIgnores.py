import Snyk

def Main():
    conn = Snyk.SnykConnection()
    conn.Create_OrgAndProjectFile()
    conn.Pull_SnykIssuesAndIgnoreInfo()
    conn.BuildExcel()

if __name__ == "__main__":  
    Main()