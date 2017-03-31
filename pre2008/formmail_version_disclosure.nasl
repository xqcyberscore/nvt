# OpenVAS Vulnerability Test
# $Id: formmail_version_disclosure.nasl 2846 2016-03-14 09:13:09Z cfi $
# Description: Formmail Version Information Disclosure
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10782");
 script_version("$Revision: 2846 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-14 10:13:09 +0100 (Mon, 14 Mar 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2001-0357");
 script_name("Formmail Version Information Disclosure");
 script_summary("Formmail Version Information Disclosure");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name:"solution", value:"Upgrade to the latest version.

 Additional information:
 http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=Formmail");
 script_tag(name:"summary", value:"Matt Wright's Formmail CGI is installed on the remote host.
 The product exposes its version number, and in addition, early versions of the product suffered
 from security vulnerabilities, which include: allowing SPAM, file disclosure, 
 environment variable disclosure, and more.");

 script_tag(name:"solution_type", value:"VendorFix");
 script_tag(name:"qod_type", value:"remote_app");

 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

files = make_list( "/formmail.pl", "/formmail.pl.cgi", "/FormMail.cgi" );

foreach dir (make_list(cgi_dirs(port:port))) {

 if(dir == "/") dir = "";

 foreach file (files)
 {
   url = string(dir, file);
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if(buf == NULL)exit(0);
   if ("Version " >< buf && buf =~ '<title>FormMail v[0-9.]+</title>')
     {
       v = ereg_replace(string: buf, replace: "\1",
			pattern: '.*<title>FormMail v([0-9.]+)</title>.*'); 
       if (v == '1.92') # Latest available version?
        {
          report =  "
Matt Wright's Formmail CGI is installed on the remote host.
The product exposes its version number.

Additional information:
http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=Formmail";
       security_message(port:port, data:report);
       exit(0);
       }
       else
       {
       report = string("\n", "Version : ", v);
       security_message(port:port, data:report);
       exit(0);
       }
     }
   else if ("FormMail</a> V" >< buf)
    {
     security_message(port:port);
     exit(0);
    }
 }
}

exit(99);