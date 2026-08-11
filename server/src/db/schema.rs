table! {
    attachments (id) {
        id -> Text,
        cipher_uuid -> Text,
        file_name -> Text,
        file_size -> BigInt,
        akey -> Nullable<Text>,
    }
}

table! {
    ciphers (uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_uuid -> Nullable<Text>,
        key -> Nullable<Text>,
        atype -> Integer,
        name -> Text,
        notes -> Nullable<Text>,
        fields -> Nullable<Text>,
        data -> Text,
        password_history -> Nullable<Text>,
        deleted_at -> Nullable<Timestamp>,
        reprompt -> Nullable<Integer>,
    }
}

table! {
    devices (uuid, user_uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_uuid -> Text,
        name -> Text,
        atype -> Integer,
        push_uuid -> Nullable<Text>,
        push_token -> Nullable<Text>,
        refresh_token -> Text,
        twofactor_remember -> Nullable<Text>,
    }
}

table! {
    favorites (user_uuid, cipher_uuid) {
        user_uuid -> Text,
        cipher_uuid -> Text,
    }
}

table! {
    folders (uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_uuid -> Text,
        name -> Text,
    }
}

table! {
    folders_ciphers (cipher_uuid, folder_uuid) {
        cipher_uuid -> Text,
        folder_uuid -> Text,
    }
}

table! {
    invitations (email) {
        email -> Text,
    }
}

table! {
    twofactor (uuid) {
        uuid -> Text,
        user_uuid -> Text,
        atype -> Integer,
        enabled -> Bool,
        data -> Text,
        last_used -> BigInt,
    }
}

table! {
    twofactor_incomplete (user_uuid, device_uuid) {
        user_uuid -> Text,
        device_uuid -> Text,
        device_name -> Text,
        device_type -> Integer,
        login_time -> Timestamp,
        ip_address -> Text,
    }
}

table! {
    twofactor_duo_ctx (state) {
        state -> Text,
        user_email -> Text,
        nonce -> Text,
        exp -> BigInt,
    }
}

table! {
    users (uuid) {
        uuid -> Text,
        enabled -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        verified_at -> Nullable<Timestamp>,
        last_verifying_at -> Nullable<Timestamp>,
        login_verify_count -> Integer,
        email -> Text,
        email_new -> Nullable<Text>,
        email_new_token -> Nullable<Text>,
        name -> Text,
        password_hash -> Binary,
        salt -> Binary,
        password_iterations -> Integer,
        password_hint -> Nullable<Text>,
        akey -> Text,
        private_key -> Nullable<Text>,
        public_key -> Nullable<Text>,
        totp_secret -> Nullable<Text>,
        totp_recover -> Nullable<Text>,
        security_stamp -> Text,
        stamp_exception -> Nullable<Text>,
        equivalent_domains -> Text,
        excluded_globals -> Text,
        client_kdf_type -> Integer,
        client_kdf_iter -> Integer,
        client_kdf_memory -> Nullable<Integer>,
        client_kdf_parallelism -> Nullable<Integer>,
        api_key -> Nullable<Text>,
        avatar_color -> Nullable<Text>,
        external_id -> Nullable<Text>,
    }
}

table! {
    auth_requests  (uuid) {
        uuid -> Text,
        user_uuid -> Text,
        request_device_identifier -> Text,
        device_type -> Integer,
        request_ip -> Text,
        response_device_id -> Nullable<Text>,
        access_code -> Text,
        public_key -> Text,
        enc_key -> Nullable<Text>,
        master_password_hash -> Nullable<Text>,
        approved -> Nullable<Bool>,
        creation_date -> Timestamp,
        response_date -> Nullable<Timestamp>,
        authentication_date -> Nullable<Timestamp>,
    }
}

table! {
    archives (user_uuid, cipher_uuid) {
        user_uuid -> Text,
        cipher_uuid -> Text,
        archived_at -> Timestamp,
    }
}

joinable!(archives -> users (user_uuid));
joinable!(archives -> ciphers (cipher_uuid));
joinable!(attachments -> ciphers (cipher_uuid));
joinable!(ciphers -> users (user_uuid));
joinable!(devices -> users (user_uuid));
joinable!(folders -> users (user_uuid));
joinable!(folders_ciphers -> ciphers (cipher_uuid));
joinable!(folders_ciphers -> folders (folder_uuid));
joinable!(twofactor -> users (user_uuid));
joinable!(auth_requests -> users (user_uuid));

allow_tables_to_appear_in_same_query!(
    archives,
    attachments,
    ciphers,
    devices,
    folders,
    folders_ciphers,
    invitations,
    twofactor,
    users,
    auth_requests,
);
