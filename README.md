# Project 3

- Name: Dolan Lavoie
- Email: dolanlavoie@u.boisestate.edu
- Class: 425-001

## Known Bugs or Issues

No

## Experience

This was an interesting project because all of these concepts are easy to think about the process in your head, but when it comes to programming them there are a lot of edge cases to worry about. A huge portion of the functions just perform bitwise operations by masking and shifting bits, which introduces edge cases around /0 and /32. It was cool to see all of the math work in the end to give the correct result. It was also much easier to know that I was on the right track because of the lab.h starting code. Being able to have the assignment cleanly broken down into functions made a huge difference as opposed to just starting from absolute scratch, both in writing the functionality but also in being able to easily test the code. This project also relied much less heavily on system and c library calls, so only a few things had to be excluded compared to the previous project, which relied very heavily on standard c library calls, so it took a bit to figure out what could actually be testing and what could be excluded. 

## Design

For /0, cidr_mask(0) returns 0 to avoid a 32 bit shift. The network is 0.0.0.0 and the broadcast is 255.255.255.255. The host count uses 64 bits to avoid an overflow. For /31, there are 2 usable addresses. cidr_first_host() returns the network address, and cidr_last_host() returns the broadcast address. For /32, there is only 1 host. The network, broadcast, first host, and last host are all the same address. 
For the longest-prefix lookup, the forwarding table stores routes in a growing array. table_lookup() then scans every route. It first checks if the destination is inside the route using the subnet mask. If it matches, it compares the route's prefix length with the best match found so far. It will select the route with the greatest prefix. For example, /25 would be selected over /24. 
