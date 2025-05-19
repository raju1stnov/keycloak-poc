FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
# Install dependencies and ensure no caching for this layer if troubleshooting
RUN pip install --no-cache-dir -r requirements.txt

# Step 1: Verify Authlib version
RUN python -c "import authlib; print(f'--- Authlib Version: {authlib.__version__} ---')"

# Step 2: Inspect the contents of authlib.jose.jwk.py
RUN echo "--- Contents of /usr/local/lib/python3.9/site-packages/authlib/jose/jwk.py ---" && \
    cat /usr/local/lib/python3.9/site-packages/authlib/jose/jwk.py && \
    echo "--- End of jwk.py ---"

# Step 3: Attempt direct import from the submodule (this is expected to fail at runtime based on current logs)
# Adding || true to ensure the build continues even if this step fails, so we can see the output
RUN python -c "print('--- Attempting direct import: from authlib.jose.jwk import JWKSet ---'); from authlib.jose.jwk import JWKSet; print('Direct import from authlib.jose.jwk successful during build.')" || (echo "Direct import from authlib.jose.jwk FAILED during build." && true)

COPY . .

EXPOSE 8000

# Using the reload for development convenience, can be removed for production or if causing issues
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
