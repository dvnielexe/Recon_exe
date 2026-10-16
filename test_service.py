from recon.modules.services import scan

results = scan("127.0.0.1", ports=[22, 80, 8000], timeout=1.0,)

for result in results:
    print(result)