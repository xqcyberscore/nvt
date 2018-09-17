###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openmrs_multiple_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# OpenMRS Multiple Security Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805009");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-8071", "CVE-2014-8072", "CVE-2014-8073");
  script_bugtraq_id(70664);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-10-29 16:11:01 +0530 (Wed, 29 Oct 2014)");

  script_name("OpenMRS Multiple Security Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with OpenMRS and
  is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The /coreapps/mergeVisits.page script does not validate input to the
    'returnUrl' parameter before returning it to users.

  - The HTTP requests to /admin/users/user.form do not require multiple steps,
    explicit confirmation, or a unique token when performing certain sensitive
    actions.

  - The /registrationapp/registerPatient.page script does not validate input to
    the 'givenName', 'familyName', 'address1', and 'address2' POST parameters
    before returning it to users.

  - The /allergyui/allergy.page script does not validate input to the 'comment'
    POST parameter before returning it to users.

  - The /htmlformentryui/htmlform/enterHtmlForm/submit.action script does not
    validate input to the 'w10' POST parameter before returning it to users.

  - The login.htm script does not validate input to the HTTP referer header
    before returning it to users.

  - The /htmlformentryui/htmlform/enterHtmlFormWithStandardUi.page script does
    not validate input to the 'returnUrl' parameter before returning it to
    users.

  - The /htmlformentryui/htmlform/enterHtmlFormWithSimpleUi.page script does
    not validate input to the 'visitId' parameter before returning it to users.

  - A lack of access restrictions for the /admin page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site and inject or manipulate SQL queries in the
  back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"OpenMRS version 2.1 Standalone Edition ");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/97690");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128748");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/openmrs", "/openmrs-standalone", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.htm"),  port:http_port);

  if(">OpenMRS - Home<" >< rcvRes && ">Powered by OpenMRS <" >< rcvRes)
  {
    url = dir + "/coreapps/mergeVisits.page?patientId=31&returnUrl=</script>" +
                "<script>alert(document.cookie);</script>";

    ## extra check is not possible
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                       pattern:"<script>alert\(document.cookie\);</script>"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
