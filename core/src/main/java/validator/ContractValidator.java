package validator;

import model.ValidationFinding;

import java.util.List;

/**
 * Base interface for all validators.
 */
public interface ContractValidator {
    /**
     * Performs validation and returns a list of findings.
     *
     * @return list of validation findings
     */
    List<ValidationFinding> validate();
}
