pipeline {
    agent any

    environment {
        CARGO_HOME = "${env.WORKSPACE}/.cargo"
        RUSTUP_HOME = "${env.WORKSPACE}/.rustup"
    }

    stages {
        stage('Checkout') {
            steps {
                echo 'Checking out code from Git...'
                checkout scm
            }
        }

        stage('Verify Environment') {
            steps {
                echo 'Verifying Rust and Cargo versions...'
                sh 'rustc --version'
                sh 'cargo --version'
            }
        }

        stage('Format Check') {
            steps {
                echo 'Checking code formatting with rustfmt...'
                sh 'cargo fmt -- --check'
            }
        }

        stage('Build') {
            steps {
                echo 'Building the Rust project...'
                sh 'cargo build --verbose'
            }
        }

        stage('Test') {
            steps {
                echo 'Running tests...'
                sh 'cargo test --verbose'
            }
        }
    }

    post {
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed. Please check the build logs for errors.'
        }
    }
}