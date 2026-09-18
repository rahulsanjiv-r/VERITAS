import re

# Fix image_store
with open('backend/image_store.py', 'r') as f:
    content = f.read()
    if 'import logging' not in content:
        content = content.replace('import sys', 'import sys\nimport logging\n\n_log = logging.getLogger(__name__)')
    content = re.sub(r'_log\.error\((.*?),\s*file=sys\.stderr\)', r'_log.error(\1)', content)
with open('backend/image_store.py', 'w') as f:
    f.write(content)

# Fix database
with open('backend/database.py', 'r') as f:
    content = f.read()
    if 'import logging' not in content:
        content = content.replace('import sys', 'import sys\nimport logging\n\n_log = logging.getLogger(__name__)')
    content = re.sub(r'_log\.error\((.*?),\s*file=sys\.stderr\)', r'_log.error(\1)', content)
with open('backend/database.py', 'w') as f:
    f.write(content)

