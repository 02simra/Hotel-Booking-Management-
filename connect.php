<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize form inputs
    $firstName = filter_var($_POST['firstName'], FILTER_SANITIZE_STRING);
    $lastName = filter_var($_POST['lastName'], FILTER_SANITIZE_STRING);
    $gender = $_POST['gender']; // Assume this is sanitized (only valid values allowed by form)
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT); // Secure password hashing
    $number = filter_var($_POST['number'], FILTER_SANITIZE_NUMBER_INT);

    // Database connection
    $conn = new mysqli('localhost', 'root', '', 'test'); // Ensure credentials are correct

    // Check for connection error
    if ($conn->connect_error) {
        die("Connection Failed: " . $conn->connect_error);
    } else {
        // Prepared statement to avoid SQL injection
        $stmt = $conn->prepare("INSERT INTO registration (firstName, lastName, gender, email, password, number) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("ssssss", $firstName, $lastName, $gender, $email, $password, $number);

        // Execute statement and check if successful
        if ($stmt->execute()) {
            echo "Registration successfully...";
        } else {
            echo "Error: " . $stmt->error;
        }

        // Close statement and connection
      $stmt->close();
      $conn->close();
      
    }
}
?>
