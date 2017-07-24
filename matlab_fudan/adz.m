function a = adz(x,num)
%UNTITLED Summary of this function goes here
%   Detailed explanation goes here
while(length(x)<num)
    x = strcat('0',x);
end;
a=x;

end

