<html>
  <p>Prime numbers from 0 to 100, calculated by Lua:</p>
 <?

    function is_prime(n)
      if n <= 0 then return false end
      if n <= 2 then return true end
      if (n % 2 == 0) then return false end
      for i = 3, n / 2, 2 do
        if (n % i == 0) then return false end
      end
      return true
    end

    for i = 1, 100 do
      if is_prime(i) then write('<span>' .. i .. '</span>&nbsp;') end
    end

 ?>

 <p>Reading POST data from Lua (click submit):</p>
 <form method="POST"><input type="text" name="t1"/><input type="submit"></form>

 <pre>
   POST data: [<?  post_data = read() write(post_data) ?>]
   request method: [<? write(request_info.request_method) ?>]
   IP/port: [<? write(request_info.remote_ip, ':', request_info.remote_port) ?>]
   URI: [<? write(request_info.uri) ?>]
   HTTP version [<? write(request_info.http_version) ?>]
   HEADERS:
   <? 
     for name, value in pairs(request_info.http_headers) do
       write(name, ':', value, '\n')
     end
   ?>
     
 </pre>


</html>
