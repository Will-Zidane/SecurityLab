# 22110172, Vũ Văn Việt
# Lab 1: Lab Buffer Overflow

# Task 1:Stack smashing by memory overwritten

## 1.1. bof1.c
 First we have a `bof1.c` file
 
    #include<stdio.h>
    #include<unistd.h>
    void secretFunc()
    {
        printf("Congratulation!\n:");
    }
    int vuln(){
        char array[200];
        printf("Enter text:");
        gets(array);
        return 0;
    }
    int main(int argc, char*argv[]){
        if (argv[1]==0){
            printf("Missing arguments\n");
        }
        vuln();
        return 0;
        
    }

## 1.2. bof2.c

![Sonny and Mariel highfiving.](https://content.codecademy.com/courses/learn-cpp/community-challenge/highfive.gif)

## 1.3. bof3.c

# Task 2: Code Injection
## 2.1. Preparing shell code

## 2.2. Preparing the payload


## 2.3. Code Injection

 
