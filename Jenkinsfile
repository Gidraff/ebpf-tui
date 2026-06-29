pipeline {
    
    agent {
    kubernetes {
        yaml '''
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: rust
    image: rust:1.76
    command: ["sleep", "infinity"]
'''
        defaultContainer 'rust'
    }
}

    environment {
        CARGO_HOME = "${env.WORKSPACE}/.cargo"
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