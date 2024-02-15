import Snyk

def Main():
    conn = Snyk.SnykConnection()
    conn.DetectStaleProjects()
          
if __name__ == "__main__":  
    Main()
