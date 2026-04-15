# =============================================================================
# iRule: LLM System Prompt Injection / Replacement Template
# 
# Author:   Allen Su
# Version:  1.0.0
# Date:     2026-03-23
# Purpose:  Intercept JSON requests to LLM completions APIs to securely append 
#           or replace the system prompt without breaking strict JSON parsing.
# Usage:    Apply this iRule to a standard Virtual Server. Modify the 'mode' 
#           and 'inject_text' variables inside HTTP_REQUEST_DATA as needed.
# Notes:    Uses string bytelength calculation to accurately adjust the HTTP 
#           Content-Length header for multi-byte UTF-8 character compatibility.
# =============================================================================

when CLIENT_ACCEPTED {
    log local0.info "CLIENT: [IP::client_addr]:[TCP::client_port] -> [IP::local_addr]:[TCP::local_port]"
}

when HTTP_REQUEST {
    set uri [HTTP::uri]
    set host [HTTP::header host]
    log local0.info "REQUEST: [IP::client_addr]:[TCP::client_port] -> $host$uri"

    # -----------------------------------------------------------------
    # Remove Accept-Encoding so error responses are readable (not gzip).
    # Remove this line in production if you don't need to debug errors.
    # -----------------------------------------------------------------
    HTTP::header remove "Accept-Encoding"

    # -----------------------------------------------------------------
    # Only intercept specific API paths. Adjust as needed.
    # -----------------------------------------------------------------
    if { $uri eq "/api/chat/completions" || $uri eq "/v1/chat/completions" } {
        if { [HTTP::header exists "Content-Length"] && [HTTP::header "Content-Length"] > 0 } {
            set content_length [HTTP::header "Content-Length"]
            # Cap at 1MB to avoid memory issues
            if { $content_length > 1048576 } {
                set content_length 1048576
            }
            # This triggers HTTP_REQUEST_DATA after payload is buffered
            HTTP::collect $content_length
        }
    }
}

when HTTP_REQUEST_DATA {
    set json_payload [HTTP::payload]

    if { [string length $json_payload] == 0 } {
        log local0.error "Empty JSON payload, passing through"
        HTTP::release
        return
    }

    # =================================================================
    # CONFIGURATION — Edit these two values
    # =================================================================

    # Mode: "append" = add to existing system prompt
    #        "replace" = completely replace the system prompt content
    set mode "append"

    # The text to inject or use as replacement.
    # Use \n for JSON newlines (inside braces, \n = literal \ + n = JSON newline).
    # Do NOT use \\n — that produces a literal backslash in the JSON output.
    set inject_text {\n\n## Your Role\nAct as a math teacher. For math queries, provide the direct answer followed by a step-by-step explanation using LaTeX for formulas. For all other topics, respond normally and conversationally. Maintain a supportive tone, ensuring explanations are clear and logical for students. And do NOT give the answer. }

    # =================================================================
    # FIND THE SYSTEM PROMPT — try common JSON formats
    # =================================================================

    # Try with spaces (pretty-printed JSON)
    set marker {"role": "system", "content": "}
    set marker_pos [string first $marker $json_payload]

    if { $marker_pos == -1 } {
        # Try without spaces (compact JSON)
        set marker {"role":"system","content":"}
        set marker_pos [string first $marker $json_payload]
    }

    if { $marker_pos >= 0 } {
        # Position right after the opening quote of the content value
        set content_start [expr { $marker_pos + [string length $marker] }]

        # ---------------------------------------------------------------
        # Walk forward to find the REAL closing quote of the content.
        # Must skip escaped characters (e.g., \", \\, \n, \t, etc.)
        # because the content will contain JSON escape sequences.
        # A simple regex like [^"]* would stop at the first \"
        # inside the content, which is wrong.
        # ---------------------------------------------------------------
        set pos $content_start
        set payload_len [string length $json_payload]
        while { $pos < $payload_len } {
            set ch [string index $json_payload $pos]
            if { $ch eq "\\" } {
                # Skip the backslash and the next character (escaped pair)
                incr pos 2
            } elseif { $ch eq "\"" } {
                # Found the real unescaped closing quote
                break
            } else {
                incr pos
            }
        }
        # $pos now points to the closing " of the system content value

        # ---------------------------------------------------------------
        # Build the new payload based on mode
        # ---------------------------------------------------------------
        if { $mode eq "replace" } {
            # REPLACE: discard original content, use inject_text as the new content
            set before [string range $json_payload 0 [expr { $content_start - 1 }]]
            set after  [string range $json_payload $pos end]
            set new_payload "${before}${inject_text}${after}"
            log local0.info "SYSTEM PROMPT REPLACED ([string length $inject_text] chars)"
        } else {
            # APPEND: keep original content, add inject_text at the end
            set before [string range $json_payload 0 [expr { $pos - 1 }]]
            set after  [string range $json_payload $pos end]
            set new_payload "${before}${inject_text}${after}"
            log local0.info "SYSTEM PROMPT APPENDED ([string length $inject_text] chars)"
        }
    } else {
        log local0.warn "No system role found in payload, passing through unchanged"
        set new_payload $json_payload
    }

    # =================================================================
    # REPLACE PAYLOAD AND FIX CONTENT-LENGTH
    #
    # CRITICAL: Use string bytelength, NOT string length!
    # Payloads often contain multi-byte UTF-8 characters (e.g., smart
    # quotes, em-dashes). string length counts characters (e.g., â = 1)
    # but Content-Length must be in bytes (e.g., â = 3 bytes in UTF-8).
    # Using string length causes Content-Length to be too small,
    # the server reads fewer bytes than the actual payload, truncates
    # the JSON, and returns 422 Unprocessable Entity.
    # =================================================================
    set orig_len  [string length $json_payload]
    set new_bytes [string bytelength $new_payload]
    HTTP::payload replace 0 $orig_len $new_payload
    HTTP::header replace "Content-Length" $new_bytes
    log local0.info "Payload: original=[string bytelength $json_payload] bytes -> new=$new_bytes bytes"

    # Save for optional server-side logging
    set flow_payload $new_payload

    HTTP::release
}

# =================================================================
# SERVER-SIDE LOGGING (optional — for debugging)
# =================================================================
when HTTP_REQUEST_SEND {
    log local0.info "FORWARDED: -> [IP::server_addr]:[TCP::server_port] Content-Length=[HTTP::header Content-Length]"
}

# =================================================================
# RESPONSE LOGGING
# =================================================================
when HTTP_RESPONSE {
    set resp_status [HTTP::status]
    log local0.info "RESPONSE: status=$resp_status Content-Type=[HTTP::header Content-Type]"

    # Collect error responses for debugging
    if { $resp_status >= 400 } {
        if { [HTTP::header exists "Content-Length"] && [HTTP::header "Content-Length"] > 0 } {
            set resp_collect [HTTP::header "Content-Length"]
            if { $resp_collect > 8192 } { set resp_collect 8192 }
        } else {
            # Chunked or unknown length
            set resp_collect 8192
        }
        HTTP::collect $resp_collect
    }
}

when HTTP_RESPONSE_DATA {
    set resp_body [HTTP::payload]
    log local0.alert "ERROR RESPONSE (status=[HTTP::status]): [string range $resp_body 0 800]"
    HTTP::release
}
