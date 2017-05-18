# OpenVAS Vulnerability Test
# $Id: http_trace.nasl 5838 2017-04-03 10:26:36Z cfi $
# Description: HTTP TRACE
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "Transparent or reverse HTTP proxies may be implement on some sites.";

# HTTP/1.1 is defined by RFC 2068
#
# Check for proxy on the way (transparent or reverse?!)

if(description)
{
 script_id(11040);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5838 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-03 12:26:36 +0200 (Mon, 03 Apr 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("HTTP TRACE");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_analysis");
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 script_family("General");
 script_dependencies("find_service.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
soc = open_sock_tcp(port);
if (!soc) exit(0);

req = http_get(port: port, item: "/");
send(socket: soc, data: req);
heads = http_recv_headers2(socket:soc);
via = egrep(pattern: "^Via: ", string: heads);
trace="";
if (via)
{
  # display(via);
  via=ereg_replace(string: via, pattern: "^Via: *", replace:"");
  via=via-string("\r\n");
  while(via)
  {
    # display("Via=", via, "\n");
    proxy = ereg_replace(string:via, pattern: " *([^,]*),?.*", replace: "\1");
    via = ereg_replace(string: via, pattern: "([^,]*)(, *)?(.*)", replace: "\3");
    # display(string("Proxy=", proxy, " - Via=", via, "\n"));
    proto = ereg_replace(string:proxy, 
		pattern:"^([a-zA-Z0-9_-]*/?[0-9.]+) +.*",
		replace: "\1");
    line = ereg_replace(string:proxy, 
		pattern:"^([a-zA-Z0-9_-]*/?[0-9.]+) *(.*)",
		replace: "\2");
    # display(string("Proto=", proto, "\nLine=", line, "\n"));
    if (egrep(pattern:"^[0-9]+", string: proto))
      proto = "HTTP/" + proto;
    trace = trace + proto;
    l = strlen(proto);
    for (i= l;i < 12; i=i+1) trace=trace+" ";
    trace=string(trace, " ", line, "\n");
  }
}

close(soc);

if (trace)
  log_message(port: port, data: string("The GET method revealed those proxies on the way to this web server :\n", trace));
else if (egrep(pattern: "^X-Cache:", string: heads))
{
  p = ereg_replace(pattern:'^X-Cache: *[A-Z]+ +from +([^ \t\r\n]+)[ \t\r\n]+',
	string: heads, replace: "\1");
  r = 'There might be a caching proxy on the way to this web server';
  if (p != heads) r = strcat(r, ':\n', p);
  log_message(port: port, data: r);
}

ver=get_kb_item(string("http/", port));
if ((ver == "10") || (ver == "09")) exit(0);	# No TRACE in HTTP/1.0

n=0;
for (i=0; i<99;i=i+1)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    req=string("TRACE / HTTP/1.1\r\n",
               "Host: ", get_host_name(), "\r\n",
               "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
               "Max-Forwards: ", i,
               "\r\n\r\n");

    send(socket: soc, data: req);
    buf = http_recv_headers2(socket:soc);
    #
    via = egrep(pattern: "^Via: ", string: buf);
    if (via)
    {
      via = ereg_replace(string: via, pattern: "^Via: *", replace:"");
      viaL[i] = via - string("\r\n");
# display(string("V[", i, "]=", viaL[i], "\n"));
    }
    else
      viaL[i] = string("?");
    #
    if (egrep(string: buf, pattern: "^HTTP/.* 200 "))
    {
      buf2 = recv_line(socket: soc, length: 2048);
      # The proxy is supposed to send back the request it got. 
      # i.e. "TRACE / HTTP/1.1"
      # However, NetCache appliance change it to "TRACE http://srv HTTP/1.1"
      if (egrep(pattern: "^TRACE (/|http://.*) HTTP/1.1", string: buf2))
      {
        srv = egrep(pattern: "^Server: ", string: buf);
        if (srv)
        {
          srv = ereg_replace(string: srv, pattern: "^Server: *", replace:"");
          srvL[i+1] = srv - string("\r\n");
# display(string("S[", i+1, "]=", srvL[i+1], "\n"));
        }
        else
          srvL[i+1] = string("?");
        n=n+1;
      }
    }
    else
      i=9999;
#
    close(soc);
  }
  else
    i = 9999;
}
  
trace="";
for (i = 1; i <= n; i = i+1)
{
  trace=string(trace, viaL[i]," - ", srvL[i], "\n");
}

if (n > 0)
  log_message(port:port, protocol:"tcp",
	data:string("The TRACE method revealed ", n, 
	" proxy(s) between us and the web server :\n",
	trace));
