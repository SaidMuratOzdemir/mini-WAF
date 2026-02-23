import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Paper,
  Stack,
  TextField,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  FormControlLabel,
  Switch,
  IconButton,
  Tooltip,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import StarIcon from '@mui/icons-material/Star';
import StarBorderIcon from '@mui/icons-material/StarBorder';

import type { Certificate } from '../types/Certificate';
import {
  deleteCertificate,
  fetchCertificates,
  setDefaultCertificate,
  uploadCertificate,
} from '../api/certificates';

interface CertificateManagerProps {
  onCertificatesChanged?: () => void;
}

export default function CertificateManager({ onCertificatesChanged }: CertificateManagerProps) {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [name, setName] = useState('');
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [chainFile, setChainFile] = useState<File | null>(null);
  const [isDefault, setIsDefault] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const loadCertificates = async () => {
    try {
      const data = await fetchCertificates();
      setCertificates(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load certificates');
    }
  };

  useEffect(() => {
    void loadCertificates();
  }, []);

  const notifyChange = () => {
    if (onCertificatesChanged) onCertificatesChanged();
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!name.trim()) {
      setError('Certificate name is required');
      return;
    }
    if (!certFile || !keyFile) {
      setError('Certificate and private key files are required');
      return;
    }

    const formData = new FormData();
    formData.append('name', name.trim());
    formData.append('is_default', String(isDefault));
    formData.append('cert_file', certFile);
    formData.append('key_file', keyFile);
    if (chainFile) formData.append('chain_file', chainFile);

    try {
      setLoading(true);
      await uploadCertificate(formData);
      setName('');
      setCertFile(null);
      setKeyFile(null);
      setChainFile(null);
      setIsDefault(false);
      await loadCertificates();
      notifyChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Certificate upload failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSetDefault = async (certificateId: number) => {
    try {
      setLoading(true);
      await setDefaultCertificate(certificateId);
      await loadCertificates();
      notifyChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to set default certificate');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (certificateId: number) => {
    try {
      setLoading(true);
      await deleteCertificate(certificateId);
      await loadCertificates();
      notifyChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete certificate');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Paper elevation={2} sx={{ p: 3, mb: 4 }}>
      <Typography variant="h6" gutterBottom>
        TLS Certificates
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box component="form" onSubmit={handleUpload}>
        <Stack spacing={2}>
          <TextField
            label="Certificate Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            fullWidth
            required
            disabled={loading}
          />

          <Button variant="outlined" component="label" disabled={loading}>
            {certFile ? `Cert: ${certFile.name}` : 'Select Certificate PEM'}
            <input
              hidden
              type="file"
              accept=".pem,.crt,.cer,.txt"
              onChange={(e) => setCertFile(e.target.files?.[0] || null)}
            />
          </Button>

          <Button variant="outlined" component="label" disabled={loading}>
            {keyFile ? `Key: ${keyFile.name}` : 'Select Private Key PEM'}
            <input
              hidden
              type="file"
              accept=".pem,.key,.txt"
              onChange={(e) => setKeyFile(e.target.files?.[0] || null)}
            />
          </Button>

          <Button variant="outlined" component="label" disabled={loading}>
            {chainFile ? `Chain: ${chainFile.name}` : 'Select Chain PEM (Optional)'}
            <input
              hidden
              type="file"
              accept=".pem,.crt,.cer,.txt"
              onChange={(e) => setChainFile(e.target.files?.[0] || null)}
            />
          </Button>

          <FormControlLabel
            control={
              <Switch
                checked={isDefault}
                onChange={(e) => setIsDefault(e.target.checked)}
                disabled={loading}
              />
            }
            label="Set as default certificate"
          />

          <Button type="submit" variant="contained" disabled={loading}>
            Upload Certificate
          </Button>
        </Stack>
      </Box>

      <Box sx={{ mt: 3 }}>
        <Typography variant="subtitle1" sx={{ mb: 1 }}>
          Registered Certificates
        </Typography>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Default</TableCell>
              <TableCell>Chain</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {certificates.map((certificate) => (
              <TableRow key={certificate.id}>
                <TableCell>{certificate.name}</TableCell>
                <TableCell>{certificate.is_default ? 'Yes' : 'No'}</TableCell>
                <TableCell>{certificate.has_chain ? 'Yes' : 'No'}</TableCell>
                <TableCell align="right">
                  <Tooltip title="Set as default">
                    <span>
                      <IconButton
                        color="primary"
                        disabled={loading || certificate.is_default}
                        onClick={() => handleSetDefault(certificate.id)}
                      >
                        {certificate.is_default ? <StarIcon /> : <StarBorderIcon />}
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title="Delete certificate">
                    <span>
                      <IconButton
                        color="error"
                        disabled={loading}
                        onClick={() => handleDelete(certificate.id)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </span>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {certificates.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} align="center">
                  No certificates uploaded yet.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Box>
    </Paper>
  );
}
