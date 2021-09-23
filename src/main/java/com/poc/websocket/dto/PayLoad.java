package com.poc.websocket.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
public class PayLoad implements Serializable {

    private static final long serialVersionUID = -6189087069983055709L;

    private String data;
}
