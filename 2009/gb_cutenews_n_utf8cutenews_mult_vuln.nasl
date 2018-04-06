###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cutenews_n_utf8cutenews_mult_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# CuteNews/UTF-8 CuteNews Multiple Vulneablities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Udated By:
# Antu Sanadi <santu@secpod.com> on 2009-12-10 #6147
# Updated the CVE's and Description
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_solution = "For UTF-8 CuteNews Upgrade to version 8b
http://korn19.ch/coding/utf8-cutenews

For CuteNews Upgrade to version 1.5.0.1 or later,
For updates refer to http://cutephp.com";

tag_impact = "Successful exploitation could allow remote attackers to steal user
credentials, disclose file contents, disclose the file path of the application,
execute arbitrary commands.

Impact Level: system/Application.";

tag_affected = "CuteNews version 1.4.6 and UTF-8 CuteNews version prior to 8b";

tag_insight = "- An improper validation of user-supplied input by the
'category.db.php' script via the Category Access field or Icon URL fields
- An improper validation of user-supplied input by the 'data/ipban.php' script
  via the add_ip paramete.
- An improper validation of user-supplied input by the 'Editnews module' via
  list or editnews parameters and 'Options module' via save_con[skin] parameter.
- An error in 'editusers' module within 'index.php' allows attackers to hijack
  the authentication of administrators for requests that create new users.
- An error in 'from_date_day' parameter to 'search.php' which reveals the
  installation path in an error message.
- An error in 'modified id' parameter in a 'doeditnews' action allows remote
  users with Journalist or Editor access to bypass administrative moderation
  and edit previously submitted articles.
- An improper validation of user-supplied input by the result parameter to
  'register.php', the user parameter to 'search.php', the cat_msg, source_msg,
  postponed_selected, unapproved_selected, and news_per_page parameters in a list
  action to the editnews module of 'index.php' and the link tag in news comments
- An error in lastusername and mod parameters to 'index.php' and the title parameter
  to 'search.php' it allow attackers to inject arbitrary web script or HTML";

tag_summary = "The host is running CuteNews/UTF-8 CuteNews and is prone to multiple
vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801056");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4113", "CVE-2009-4116", "CVE-2009-4115", "CVE-2009-4174",
                "CVE-2009-4175", "CVE-2009-4173", "CVE-2009-4172","CVE-2009-4250",
                "CVE-2009-4249");
  script_bugtraq_id(36971);
  script_name("CuteNews/UTF-8 CuteNews Multiple Vulneablities");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54243");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/507782/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.morningstarsecurity.com/advisories/MORNINGSTAR-2009-02-CuteNews.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("cutenews_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

cnPort = get_http_port(default:80);
if(!cnPort){
  exit(0);
}


# Check for CuteNews version 1.4.6
cnVer = get_kb_item("www/" + cnPort + "/cutenews");
if(cnVer)
{
  cnVer = eregmatch(pattern:"^(.+) under (/.*)$", string:cnVer);
  if(!safe_checks() && cnVer[2] != NULL)
  {
    request = http_get(item:cnVer[2] + "/index.php?lastusername='><script>" +
                            "alert(/OpenVAS-XSS/);</script>", port:cnPort);
    response = http_send_recv(port:cnPort, data:request);
    if(response =~ "HTTP/1\.. 200" && "<script>alert(/OpenVAS-XSS/);</script>" >< response)
    {
      security_message(cnPort);
      exit(0);
    }
  }

  if(cnVer[1] != NULL)
  {
    if(version_is_equal(version:cnVer[1], test_version:"1.4.6"))
    {
      security_message(cnPort);
      exit(0);
    }
  }
}

# Checking for UTF-8 CuteNews version prior to 8b
ucnVer = get_kb_item("www/" + cnPort + "/UTF-8/cutenews");
if(ucnVer)
{
  ucnVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ucnVer);
  if(!safe_checks() && ucnVer[2] != NULL)
  {
    request = http_get(item:string(ucnVer[2] + '/search.php?user="><script>' +
                            'alert(/OpenVAS-XSS/);</script>'), port:cnPort);
    response = http_send_recv(port:cnPort, data:request);
    if(response =~ "HTTP/1\.. 200" && "<script>alert(/OpenVAS-XSS/);</script>" >< response)
    {
      security_message(cnPort);
      exit(0);
    }
  }

  if(ucnVer[1] != NULL)
  {
    if(version_is_less(version:ucnVer[1], test_version:"8b")){
      security_message(cnPort);
    }
  }
}
