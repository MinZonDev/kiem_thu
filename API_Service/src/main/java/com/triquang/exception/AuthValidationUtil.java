package com.triquang.exception;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AuthValidationUtil {

    public static boolean isValidPassword(String password) {
        // Kiểm tra mật khẩu có ít nhất 1 chữ in hoa, 1 chữ thường, 1 số, 1 kí tự đặc biệt và độ dài từ 8 kí tự
        String passwordRegex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$";
        Pattern pattern = Pattern.compile(passwordRegex);
        Matcher matcher = pattern.matcher(password);
        return matcher.matches();
    }

    public static boolean isValidEmail(String email) {
        // Kiểm tra định dạng email
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        Pattern pattern = Pattern.compile(emailRegex);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }
}

