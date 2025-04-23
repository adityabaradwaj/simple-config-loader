use std::env;
use std::str::FromStr;
use std::sync::OnceLock;

use anyhow::Result;
use config::{Case, FileFormat};
use serde::de::DeserializeOwned;
use simple_encrypt::decrypt_file;

#[derive(strum::EnumString, strum::Display)]
#[strum(serialize_all = "lowercase")]
enum Environment {
    Dev,
    Stag,
    Prod,
}

static CONFIG: OnceLock<config::Config> = OnceLock::new();

pub fn init_default() {
    CONFIG.get_or_init(|| read_config_vars_from_all_sources(None, vec![]).unwrap());
}

pub fn init(prefix: Option<String>, list_parse_keys: Vec<String>) {
    CONFIG.get_or_init(|| read_config_vars_from_all_sources(prefix, list_parse_keys).unwrap());
}

// Order of precedence (highest to lowest):
// 1. Env vars
// 2. local.env / local-secrets.env.enc
// 3. <env>.env / <env>-secrets.env.enc
// 4. default.env / default-secrets.env.enc
// 5. local.yaml / local-secrets.yaml.enc
// 6. <env>.yaml / <env>-secrets.yaml.enc
// 7. default.yaml / default-secrets.yaml.enc
fn read_config_vars_from_all_sources(
    prefix: Option<String>,
    list_parse_keys: Vec<String>,
) -> Result<config::Config> {
    let config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| {
        println!("CONFIG_DIR is not set, defaulting to config in the same folder");
        "./conf".into()
    });

    let env = env::var("ENV").unwrap_or_else(|_| {
        println!("ENV is not set, defaulting to dev environment");
        "dev".into()
    });
    let env = Environment::from_str(&env).expect("Invalid value for ENV");

    // dotenvy::from_path does NOT override existing env vars
    // So loading in this order ensures that pre-existing env vars take precedence,
    // while env vars in the files override each other in the appropriate order
    dotenvy::from_path(format!("{config_dir}/.env")).ok();
    dotenvy::from_path(format!("{config_dir}/local.env")).ok();
    dotenvy::from_path(format!("{config_dir}/{env}.env")).ok();
    dotenvy::from_path(format!("{config_dir}/default.env")).ok();

    let secrets_encryption_key_b64 = env::var("SECRETS_ENCRYPTION_KEY").ok();
    if secrets_encryption_key_b64.is_none() {
        println!("SECRETS_ENCRYPTION_KEY not found, not loading encrypted secrets");
    }

    if let Some(ref key) = secrets_encryption_key_b64 {
        if let Ok(decrypted) = decrypt_file(&format!("{config_dir}/{env}-secrets.env.enc"), key) {
            dotenvy::from_read(decrypted.as_slice())?;
        } else {
            // println!("Couldn't find or failed to decrypt
            // {env}-secrets.env.enc, not loading encrypted secrets");
        }
    }

    let mut config_builder = config::Config::builder()
        // Start off by merging in the "default" configuration file
        .add_source(config::File::new(
            &format!("{config_dir}/default.yaml"),
            FileFormat::Yaml,
        ).required(false))
        // Add in the current environment file
        .add_source(config::File::new(
            &format!("{config_dir}/{env}"),
            FileFormat::Yaml,
        ).required(false))
        // Add in the secrets file for the current environment, which might be used as plaintext
        // during local development. This file shouldn't be checked in to git
        .add_source(
            config::File::new(
                &format!("{config_dir}/{env}-secrets.yaml"),
                FileFormat::Yaml,
            )
            .required(false),
        );

    if let Some(ref key) = secrets_encryption_key_b64 {
        if let Ok(decrypted) = decrypt_file(&format!("{config_dir}/{env}-secrets.yaml.enc"), key) {
            config_builder = config_builder.add_source(config::File::from_str(
                &String::from_utf8(decrypted)?,
                FileFormat::Yaml,
            ).required(false));
        }
        if let Ok(decrypted) = decrypt_file(&format!("{config_dir}/local-secrets.yaml.enc"), key) {
            config_builder = config_builder.add_source(config::File::from_str(
                &String::from_utf8(decrypted)?,
                FileFormat::Yaml,
            ).required(false));
        }
    };

    config_builder = config_builder
        // Add in a local configuration file
        // This file shouldn't be checked in to git
        // Note that this file is _optional_
        .add_source(config::File::new(
            &format!("{config_dir}/local.yaml"),
            FileFormat::Yaml,
        ).required(false));

    let mut env_source = if let Some(prefix) = prefix {
        config::Environment::with_prefix(&prefix).prefix_separator("__").convert_case(Case::Lower)
    } else {
        config::Environment::default().convert_case(Case::Lower)
    }
    .separator("__");
    // We have to hardcode the list of config vars across the entire application
    // that must be parsed as Vec<String> rather than String
    if !list_parse_keys.is_empty() {
        env_source = env_source.list_separator(",").try_parsing(true);
        for key in list_parse_keys {
            env_source = env_source.with_list_parse_key(&key);
        }
    }
    // Add in settings from the environment (with a prefix of <prefix>)
    // Eg.. `AST__DEBUG=1 ./target/server` would set the `debug` key
    config_builder = config_builder.add_source(env_source);

    Ok(config_builder.build()?)
}

pub trait LoadConfig: DeserializeOwned {
    fn load() -> Self {
        CONFIG.get().unwrap().clone().try_deserialize().unwrap()
    }
}
