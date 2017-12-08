# OpenVAS Vulnerability Test
# $Id: ibillpm_detect.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: ibillpm.pl
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
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

tag_summary = "The 'ibillpm.pl' CGI is installed.
Some versions of this CGI use a weak password management system
that can be brute-forced.

** No flaw was tested. Your script might be a safe version.

Solutions : upgrade the script if possible. If not:
1) Move the script elsewhere (security through obscurity)
2) Request that iBill fix it.
3) Configure your web server so that only addreses from ibill.com
   may access it.";

# References:
# Date:  Thu, 25 Oct 2001 12:21:37 -0700 (PDT)
# From: "MK Ultra" <mkultra@dqc.org>
# To: bugtraq@securityfocus.com
# Subject: Weak authentication in iBill's Password Management CGI

if(description)
{
 script_id(11083);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2001-0839");
 script_bugtraq_id(3476);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  
 name = "ibillpm.pl";
 script_name(name);
 



 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");

 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"ibillpm.pl", port:port);
if(res)security_message(port);
# Note: we could try to access it. If we get a 403 the site is safe.
