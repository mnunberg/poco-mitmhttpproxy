package Proxy::AntiModal;
use strict;

our $Code = <<END_CODE
<script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.4/jquery.min.js"></script>
  <script type="text/javascript">
    \$(document).ready(function() {
         var window_width = \$(window).width();
         var window_height = \$(window).height();
         
         var temp_attr = 0;
         var mask = 0;

         \$('body div,body table,body iframe').each(function() {
              var div_width = \$(this).width();
              var div_height = \$(this).height();
              if(div_width == window_width && div_height == window_height) {
                   mask = \$(this).css('z-index');
                 \$(this).remove();
              }
              else {
                   temp_attr = \$(this).css('z-index');
    
                   if(temp_attr > mask && temp_attr!='auto') {
                        \$(this).remove();
                   }
              }
         });
    });
    </script>
END_CODE

