use actix_web::{
    App, HttpResponse, HttpServer, Responder, Result,
    body::BoxBody,
    dev::ServiceResponse,
    error,
    http::{StatusCode, header::ContentType},
    middleware::{ErrorHandlerResponse, ErrorHandlers},
    post, web,
};
use base64::{Engine, engine::general_purpose};
use derive_more::derive::{Display, Error};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use solana_sdk::{bs58, instruction::Instruction, pubkey, signature::Keypair, signer::Signer};
use spl_token::ID as TOKEN_PROGRAM_ID;
use spl_token::instruction::initialize_mint2;
use std::str::FromStr;

#[derive(Debug, Display, Error)]
#[display("app error: {msg}")]
struct AppError {
    msg: &'static str,
}

pub struct SerializableInstruction(pub Instruction);

impl Serialize for SerializableInstruction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let instr = self.0.clone();

        let mut state = serializer.serialize_struct("Instruction", 3)?;
        state.serialize_field("program_id", &instr.program_id.to_string())?;

        let accounts_json: Vec<_> = instr
            .accounts
            .iter()
            .map(|account| {
                serde_json::json!({
                    "pubkey": account.pubkey.to_string(),
                    "is_signer": account.is_signer,
                    "is_writable": account.is_writable
                })
            })
            .collect();

        state.serialize_field("accounts", &accounts_json)?;
        state.serialize_field(
            "instruction_data",
            &general_purpose::STANDARD.encode(&instr.data),
        )?;
        state.end()
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    data: String,
}

impl error::ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .json(ErrorResponse {
                success: false,
                data: self.msg.to_string(),
            })
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

#[derive(Serialize)]
struct AppResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct GenKpResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenBody {
    #[serde(alias = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[post("/keypair")]
async fn generate_keypair() -> Result<impl Responder> {
    let kp = Keypair::new();
    let obj = AppResponse {
        success: true,
        data: GenKpResponse {
            pubkey: bs58::encode(kp.pubkey()).into_string(),
            secret: bs58::encode(kp.secret_bytes()).into_string(),
        },
    };
    Ok(web::Json(obj))
}

#[post("/token/create")]
async fn create_token(body: web::Json<CreateTokenBody>) -> Result<impl Responder, AppError> {
    let mint_pubkey = match pubkey::Pubkey::from_str(&body.mint) {
        Ok(key) => key,
        Err(_) => {
            return Err(AppError {
                msg: "Invalid mint key",
            });
        }
    };

    let mint_authority_pubkey = match pubkey::Pubkey::from_str(&body.mint_authority) {
        Ok(key) => key,
        Err(_) => {
            return Err(AppError {
                msg: "Invalid mint authority key",
            });
        }
    };

    let ix = match initialize_mint2(
        &TOKEN_PROGRAM_ID,
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        body.decimals,
    ) {
        Ok(ix) => ix,
        Err(_) => {
            return Err(AppError {
                msg: "Couldn't formulate the instruction",
            });
        }
    };

    Ok(web::Json(AppResponse {
        success: true,
        data: SerializableInstruction(ix),
    }))
}

fn json_error_handler<B>(res: ServiceResponse<B>) -> Result<ErrorHandlerResponse<BoxBody>> {
    let status = res.status();

    let error_response = AppResponse {
        success: false,
        data: "error",
    };

    let body = match serde_json::to_string(&error_response) {
        Ok(body) => body,
        Err(_) => "{\"error\": \"Serialization Error\", \"message\": \"Could not generate error message\"}".into(),
    };

    let response = res.into_response(
        HttpResponse::build(status)
            .insert_header(ContentType::json())
            .body(body)
            .map_into_left_body(), // Convert to EitherBody::Left(BoxBody)
    );

    Ok(ErrorHandlerResponse::Response(response))
}

#[derive(Serialize, Deserialize)]
struct SignMsgBody {
    message: String,
    secret: String,
}

#[derive(Serialize, Deserialize)]
struct SignMsgResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[post("/message/sign")]
async fn sign_message(body: web::Json<SignMsgBody>) -> Result<impl Responder, AppError> {
    let msg = &body.message;
    let kp = Keypair::from_base58_string(&body.secret);

    let signature = kp.sign_message(&msg.as_bytes());

    Ok(web::Json(AppResponse {
        success: true,
        data: SignMsgResponse {
            signature: general_purpose::STANDARD
                .encode(signature.as_array())
                .to_string(),
            public_key: bs58::encode(kp.pubkey().to_bytes()).into_string(),
            message: msg.clone(),
        },
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Server running at http://0.0.0.0:3000");

    HttpServer::new(move || {
        App::new()
            .wrap(ErrorHandlers::new().default_handler(json_error_handler))
            .service(generate_keypair)
            .service(create_token)
            .service(generate_keypair)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}
