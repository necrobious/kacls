TARGET = aarch64-unknown-linux-gnu
#TARGET = aarch64-unknown-linux-musl

.PHONY: deploy clean build synth

cargo_build:
	cargo lambda build --release --output-format zip --target $(TARGET)

delete_zip:
	find target -name bootstrap.zip -exec rm -fv {} \;

remove_cdk_out:
	rm -rf cdk.out

cargo_clean:
	cargo clean

test_authentication_jwt:
	jwt encode --secret @key.pem --alg "RS256" --kid "test-key-42" --exp "+30d" --aud "intended_audience" --iss "trusted_issuer" '{"email":"kirk@enterprise.com"}'

test_authorization_jwt:
	jwt encode --secret @key.pem --alg "RS256" --kid "test-key-42" --exp "+30d" --aud "intended_audience" --iss "trusted_issuer" '{"email":"kirk@enterprise.com", "kacls_url":"https://api.kacls.com/v20230102", "resource_name":"some_resource_name", "role":"writer"}'

deploy: cargo_build cdk_deploy
synth: cargo_build cdk_synth
build: delete_zip cargo_build 
clean: cargo_clean remove_cdk_out
