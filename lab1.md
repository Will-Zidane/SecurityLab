# 19110113, Phạm Ngọc Duy Đan
# Lab 1: Lab Buffer Overflow

# Task 1:Stack smashing by memory overwritten

## 1.1. bof1.c
 First we have a `bof1.c` file:
 
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
I see that we have a array with 200 charaters,then i use `gcc` to compile `bof1.c` file:

![Comepile gcc bof1.c](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2018.51.33.png?raw=true)

We can see the warning that the `gets` function is dangerous and that will be the vulnerable for we to make the program have buffer overflow. We will run `gdb` for the first time:

![Comepile gcc bof1.c](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2018.53.32.png?raw=true)

From this we will try to make buffer overflow to make it overflow in **EIP**. I will try to press 204 letter a in the first time:

![Comepile 204 letters a bof1.c](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2018.57.23.png?raw=true)

So the program still not broken, we will try 208 letters a and we see `SIGSEGV` program and it overflow down to `SP`:

![Comepile 208 letters a bof1.c](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2019.02.03.png?raw=true)

We keep continue 212 letters a and 4 letters d:

![Comepile 212 letters a and 4 letters d bof1.c](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2019.05.24.png?raw=true)

Seeing that the $PC address corresponds to 4 d's, we overflow it, then here we can exploit and change the control direction with 212 a's and 4 hex digits corresponding to the address we need to navigate. And we can see that in `bof1.c` have `secretFunc` function:

![Comepile 212 letters a and 4 letters d bof1.c](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/code.png?raw=true)

So we can use `disas main` to see the address of this function:

![Comepile 212 letters a and 4 letters d bof1.c](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2019.17.42.png?raw=true)

From this we can know that `secretFunc` address is `0x0804846b` ,then we will use print function of python and give payload to 1 text file.

**INPUT**:`python -c "print('a'*212+'\x6b\x84\x04\x08')" > inputbof1`

![Comepile 212 letters a and 4 letters d bof1.c](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2019.36.57.png?raw=true)

And we run gdb from that `inputbof1` we will have result:

![Comepile 212 letters a and 4 letters d bof1.c](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2019.36.30.png?raw=true)


## 1.2. bof2.c

We have `bof2.c` file:

    #include <stdlib.h>
    #include <stdio.h>
    
    void main(int argc, char *argv[])
    {
      int var;
      int check = 0x04030201;
      char buf[40];
    
      fgets(buf,45,stdin);
    
      printf("\n[buf]: %s\n", buf);
      printf("[check] 0x%x\n", check);
    
      if ((check != 0x04030201) && (check != 0xdeadbeef))
        printf ("\nYou are on the right way!\n");
    
      if (check == 0xdeadbeef)
       {
         printf("Yeah! You win!\n");
       }
    }


Through the source we can see there are 2 if lines
In the first if line, when t overflows the check variable, it will notify you that you are on the right track
In the second if line, when t manipulates and changes the value of check to deadbeef, we finish the lab. First we use `gcc` to deploy the program:


![Sonny and Mariel highfiving.](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2019.42.38.png?raw=true)

Just like the previous lesson, we will exploit the vulnerability of the gets() function. When the input overflows the value, it will overflow below the stack frame.
So first I tried entering 41 letters a:

![Sonny and Mariel highfiving.](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2019.53.33.png?raw=true)

We see that a letter a has been inserted into the check variable
So we only need to insert 40 letters a and insert the word deadbeef to complete:

![Sonny and Mariel highfiving.](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2019.56.53.png?raw=true)


## 1.3. bof3.c
First we have `bof3.c` file:

    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/types.h>
    #include <unistd.h>
    
    void shell() {
        printf("You made it! The shell() function is executed\n");
    }
    
    void sup() {
        printf("Congrat!\n");
    }
    
    void main()
    { 
        int var;
        void (*func)()=sup;
        char buf[128];
        fgets(buf,133,stdin);
        func();
    }

Similar to bof1.c, we see there are 3 functions: Main() function, sup() function and shell() function (the function we need to navigate to) and this C program also uses fgets() function which is a function with broken buffer overflow
I use gcc to compile the program to put it into gdb:



![Sonny and Mariel highfiving.](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2020.03.33.png?raw=true)

![Sonny and Mariel highfiving.](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2020.04.03.png?raw=true)

Seeing the string buf[128], we will exploit it by entering 128 letters a and any 4 bytes of characters to see if it has overflowed to EIP:


![Sonny and Mariel highfiving.](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2020.09.29.png?raw=true)

Here I see that the 4 d's I entered have been inserted into EIP, so the off set of this program will be 128 + "function address to navigate"
Continue searching for the address of the shell() function using the command in gdb

![Sonny and Mariel highfiving.](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2020.09.29.png?raw=true)


We can see the address of shell() function is `0x804845b`.

![Sonny and Mariel highfiving.](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2020.14.04.png?raw=true)

**INPUT**: `python -c "print('a'*128+'\x5b\x84\x04\x08')"` > inputbof3
Just like in the first lesson, I save this input into a text file and then use file text to run the program in gdb:

![Sonny and Mariel highfiving.](https://github.com/Will-Zidane/SecurityLab/blob/main/Photo/Screenshot%202024-06-27%20at%2020.37.43.png?raw=true)

# Task 2: Code Injection
## 2.1. Preparing shell code

## 2.2. Preparing the payload


## 2.3. Code Injection

 
