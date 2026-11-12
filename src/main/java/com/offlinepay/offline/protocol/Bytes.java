package com.offlinepay.offline.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.BufferUnderflowException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Small big-endian byte reader/writer used by every message format. */
final class Bytes {

    private Bytes() {}

    static String toBase64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    static byte[] fromBase64Url(String text) {
        if (text == null) throw new ProtocolException("Empty payload");
        try {
            return Base64.getUrlDecoder().decode(text.trim());
        } catch (IllegalArgumentException e) {
            throw new ProtocolException("Payload is not valid base64url");
        }
    }

    static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Writer u8(int v) {
            out.write(v & 0xFF);
            return this;
        }

        Writer u16(int v) {
            out.write((v >>> 8) & 0xFF);
            out.write(v & 0xFF);
            return this;
        }

        Writer i64(long v) {
            out.writeBytes(ByteBuffer.allocate(8).putLong(v).array());
            return this;
        }

        Writer raw(byte[] b) {
            out.writeBytes(b);
            return this;
        }

        /** 1-byte length prefix, max 255 bytes. */
        Writer short8(byte[] b) {
            if (b.length > 255) throw new ProtocolException("Field too long");
            return u8(b.length).raw(b);
        }

        /** 2-byte length prefix, max 65535 bytes. */
        Writer long16(byte[] b) {
            if (b.length > 65535) throw new ProtocolException("Field too long");
            return u16(b.length).raw(b);
        }

        Writer text8(String s) {
            return short8(s.getBytes(StandardCharsets.UTF_8));
        }

        byte[] toBytes() {
            return out.toByteArray();
        }
    }

    static final class Reader {
        private final ByteBuffer buf;

        Reader(byte[] data) {
            this.buf = ByteBuffer.wrap(data);
        }

        int position() {
            return buf.position();
        }

        int u8() {
            try {
                return buf.get() & 0xFF;
            } catch (BufferUnderflowException e) {
                throw new ProtocolException("Payload is truncated");
            }
        }

        int u16() {
            return (u8() << 8) | u8();
        }

        long i64() {
            try {
                return buf.getLong();
            } catch (BufferUnderflowException e) {
                throw new ProtocolException("Payload is truncated");
            }
        }

        byte[] raw(int n) {
            if (n < 0 || buf.remaining() < n) throw new ProtocolException("Payload is truncated");
            byte[] b = new byte[n];
            buf.get(b);
            return b;
        }

        byte[] short8() {
            return raw(u8());
        }

        byte[] long16() {
            return raw(u16());
        }

        String text8() {
            return new String(short8(), StandardCharsets.UTF_8);
        }

        void expectEnd() {
            if (buf.hasRemaining()) throw new ProtocolException("Unexpected trailing bytes");
        }
    }
}
