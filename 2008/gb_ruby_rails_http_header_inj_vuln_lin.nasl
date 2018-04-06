###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rails_http_header_inj_vuln_lin.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Ruby on Rails redirect_to() HTTP Header Injection Vulnerability - Linux
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_solution = "Upgrade to higher Version or Apply patches from,
  http://github.com/rails/rails/commit/7282ed863ca7e6f928bae9162c9a63a98775a19d

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful attack could lead to execution of arbitrary HTML or scripting code
  in the context of an affected application or allow Cross Site Request Forgery
  (CSRF), Cross Site Scripting (XSS) and HTTP Request Smuggling Attacks.
  Impact Level: Application";
tag_affected = "Ruby on Rails Version before 2.0.5 on Linux.";
tag_insight = "Input passed to the redirect_to() function is not properly sanitized before
  being used.";
tag_summary = "The host is running Ruby on Rails, which is prone to HTTP Header
  Injection Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800144");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5189");
  script_bugtraq_id(32359);
  script_name("Ruby on Rails redirect_to() HTTP Header Injection Vulnerability - Linux");

  script_xref(name : "URL" , value : "http://weblog.rubyonrails.org/2008/10/19/response-splitting-risk");
  script_xref(name : "URL" , value : "http://www.rorsecurity.info/journal/2008/10/20/header-injection-and-response-splitting.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("http_func.inc");
include("ssh_func.inc");
include("version_func.inc");

port = 3000;

if (!get_port_state(port))
  exit (0);

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

sndReq = string("GET /", "\r\n",
                "Host: ", get_host_name(), ":", port, "\r\n");
send(socket:soc, data:sndReq);
if("Ruby on Rails" >!< recv(socket:soc, length:1024))
{
  close(soc);
  exit(0);
}
close(soc);

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

railsFile = find_file(file_name:"rails", file_path:"/", useregex:TRUE,
                      regexpar:"$", sock:sock);
foreach binFile (railsFile)
{
  railsVer = get_bin_version(full_prog_name:chomp(binFile), version_argv:"-v",
                             ver_pattern:"Rails ([0-9.]+)", sock:sock);
  if(railsVer[1] != NULL)
  {
    if(version_is_less(version:railsVer[1], test_version:"2.0.5")){
      security_message(port);
    }
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();
