package com.cos.security1.config.oauth.provider;

// ClientRegistration ,Attributes 정보를 처리하는 메소드들
public interface OAuth2UserInfo {

    String getProviderId();

    String getProvider();

    String getEmail();

    String getName();
}
