<html>
<body>
<center><b>VazaGet server!</b></center>
<hr>
<?php if (!empty($_SERVER['REMOTE_ADDR'])) echo "ClientSrcIP=" .  $_SERVER['REMOTE_ADDR'] . "<br />"; ?>
<?php if (!empty($_SERVER['REMOTE_PORT'])) echo "ClientSrcPort=" .  $_SERVER['REMOTE_PORT'] . "<br />"; ?>
<?php if (!empty($_SERVER['SERVER_ADDR'])) echo "ClientDstIP=" .  $_SERVER['SERVER_ADDR'] . "<br />"; ?>
<?php if (!empty($_SERVER['SERVER_PORT'])) echo "ClientDstPort=" .  $_SERVER['SERVER_PORT'] . "<br />"; ?>
<?php if (!empty($_SERVER['SERVER_PROTOCOL'])) echo "HttpProtocol=" .  $_SERVER['SERVER_PROTOCOL'] . "<br />"; ?>
<?php if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) echo "X-ForwardedFor=" .  $_SERVER['HTTP_X_FORWARDED_FOR'] . "<br />"; ?>
<?php if (!empty($_SERVER['HTTP_COOKIE'])) echo "HttpCookie=" .  $_SERVER['HTTP_COOKIE'] . "<br />"; ?>
<?php if (!empty($_SERVER['HTTP_VIA'])) echo "HttpVia=" .  $_SERVER['HTTP_VIA'] . "<br />"; ?>
<?php if (!empty($_SERVER['SSL_SESSION_ID'])) echo "SSLSessionID=" .  $_SERVER['SSL_SESSION_ID'] . "<br />"; ?>
<hr>
<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post" enctype="multipart/form-data">
<label for="file">File upload (POST test):</label>
<input type="file" name="file" id="file"><br>
<input type="submit" name="submit" value="Submit">
</form>

<?php
if(isset($_POST['submit']))
{
	$allowedExts = array("gif", "jpeg", "jpg", "png", "vzg" , "txt");
	$extension = end(explode(".", $_FILES["file"]["name"]));
	if ((($_FILES["file"]["type"] == "image/gif")
	|| ($_FILES["file"]["type"] == "image/jpeg")
	|| ($_FILES["file"]["type"] == "image/jpg")
	|| ($_FILES["file"]["type"] == "image/pjpeg")
	|| ($_FILES["file"]["type"] == "image/x-png")
	|| ($_FILES["file"]["type"] == "image/png")
	|| ($_FILES["file"]["type"] == "application/octet-stream")
	|| ($_FILES["file"]["type"] == "text/plain"))
	&& in_array($extension, $allowedExts))
	{
		if ($_FILES["file"]["error"] > 0)
		{
			echo "Return Code: " . $_FILES["file"]["error"] . "<br>";
		}
		else
		{
			$dir_path = "/dev/null";
			echo "Success Upload file--> ";
			echo $_FILES["file"]["name"] . " , size=" . ($_FILES["file"]["size"] / 1024) . " kB" . "<br>";

			if (file_exists($dir_path . $_FILES["file"]["name"]))
			{
				echo $_FILES["file"]["name"] . " already exists. ";
			}
			else
			{
				move_uploaded_file($_FILES["file"]["tmp_name"],
				$dir_path . $_FILES["file"]["name"]);
			}
		}
	}
	else
	{
		echo "!!!Invalid file type!!!, allowed-->";
		foreach($allowedExts as $v) echo "*." . $v , PHP_EOL;
	}
}
?>
</body>
</html>

