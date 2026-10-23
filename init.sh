export UV_PROJECT_ENVIRONMENT="$HOME/venv/a2aS"
uv sync
source "$UV_PROJECT_ENVIRONMENT/bin/activate"



export GOOGLE_CLOUD_PROJECT=qwiklabs-gcp-00-8947d785cf88
export GOOGLE_CLOUD_LOCATION="global"
export GOOGLE_GENAI_USE_VERTEXAI="True"
export GEMINI_MODEL="gemini-3.6-flash"
export GEMINI_JUDEGE="gemini-3.1-pro-rev"