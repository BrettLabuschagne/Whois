<?php

class Whois_domain {

        var $possible_tlds;
        var $whois_server;
        var $free_string;
        var $whois_param;
        var $domain;
        var $tld;
        var $compl_domain;
        var $full_info;
        var $msg;
        var $info;
        var $os_system = "win"; // switch between "linux" and "win"
         
        function Whois_domain() {
                $this->info = "";
                $this->msg = "";
        }
        function process() {
                if ($this->create_domain()) {
                        if ($this->full_info == "yes") {
                                $this->get_domain_info();
                        } else {
                                if ($this->check_only() == 1) {
                                        $this->msg = "The domain name: <b>".$this->compl_domain."</b> is free.";
                                        return true;
                                } elseif ($this->check_only() == 0) {
                                        $this->msg = "The domain name: <b>".$this->compl_domain."</b> is registered";
                                        return false;
                                } else {
                                        $this->msg = "There was something wrong, try it again.";
                                }
                        }
                } else {
                        $this->msg = "Only letters, numbers and hyphens (-) are valid!";
                }
        }
        function check_entry() {
                if (preg_match("/^([a-z0-9]+(\-?[a-z0-9]*)){2,63}$/i", $this->domain)) {
                        return true;
                } else {
                        return false;
                }
        }
        function create_tld_select() {
                $menu = "<select name=\"tld\" style=\"margin-left:0;\">\n";
                foreach ($this->possible_tlds as $val) {
                        $menu .= "  <option value=\"".$val."\"";
                        $menu .= (isset($_POST['tld']) && $_POST['tld'] == $val) ? " selected=\"selected\">" : ">";
                        $menu .= $val."</option>\n";
                }
                $menu .= "</select>\n";
                return $menu;
        }
        function create_domain() {
                if ($this->check_entry()) {
                        $this->domain = strtolower($this->domain);
                        $this->compl_domain = $this->domain.".".$this->tld;
                        return true;
                } else {
                        return false;
                }
        }
        function check_only() {
                $data = $this->get_whois_data();
                if (is_array($data)) {
                        $found = 0;
                        foreach ($data as $val) {
                                if (stristr($val, $this->free_string)) {
                                        $found = 1;
                                } 
                        }
                        return $found;
                } else {
                        $this->msg = "Error, please try it again.";
                }
        }
        function get_domain_info() {
                if ($this->create_domain()) {
                        $data = ($this->tld == "nl") ? $this->get_whois_data(true) : $this->get_whois_data();
                        //print_r($data);
                        if (is_array($data)) {
                                foreach ($data as $val) {
                                        if (stristr($val, $this->free_string)) {
                                                $this->msg = "The domain name: <b>".$this->compl_domain."</b> is free.";
                                                $this->info = "";
                                                break;
                                        }
                                        $this->info .= $val;
                                }
                        } else {
                                $this->msg = "Error, please try it again.";
                        }
                } else {
                        $this->msg = "Only letters, numbers and hyphens (-) are valid!";
                }
        }
        function get_whois_data($empty_param = false) { 
        // the parameter is new since version 1.20 and is used for .nl (dutch) domains only
                if ($empty_param) {
                        $this->whois_param = "";
                }
                if ($this->tld == "de") $this->os_system = "win"; // this tld must be queried with fsock otherwise it will not work
                //if ($this->tld == "co.za") $this->os_system = "win"; // this tld must be queried with fsock otherwise it will not work
                if ($this->os_system == "win") {
                        #print "RUNNING WINDOWS\n";
                        $connection = @fsockopen($this->whois_server, 43);
                        if (!$connection) {
                                unset($connection);
                                $this->msg = "Can't connect to the server!";
                                return;
                        } else {
                                sleep(2);
                                fputs($connection, $this->whois_param.$this->compl_domain."\r\n");
                                while (!feof($connection)) {
                                        $buffer[] = fgets($connection, 4096);
                                }
                                fclose($connection);
                        }
                } else {

                        $string = "whois -h ".$this->whois_server." \"".$this->whois_param.$this->compl_domain."\""; 
                        $string = str_replace (";", "", $string).";";
                        #print "RUNNING COMMAND $string\n";
                        exec($string, $buffer);


                }
                if (isset($buffer)) {
                        //print_r($buffer);
                        return $buffer;
                } else {
                        $this->msg = "Can't retrieve data from the server!";
                }
        }
}
?>