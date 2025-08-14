import markdown

md = markdown.Markdown(extensions=[])

def parse_markdown(data: str):
    # Convert Markdown to HTML
    return md.convert(data)
