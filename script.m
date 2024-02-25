numNodes = 5000;
gridSize = 200;
transmissionRange = 30;
simulationDuration = 200;
initialEnergy = 2000;
numEntries = 400;
nodeMobility = 5;

nodePositions = gridSize * rand(numNodes, 2);

sinkholeResults = table('Size', [0, 12], 'VariableNames', {'EntryIndex','Node', 'AttackType', 'TimeStep', 'InitialEnergy', 'EnergyLevel', 'EnergyDrained', 'ActualEnergyConsumed', 'ActualAttackSuccessRate', 'AttackDuration', 'IPS_Prevented', 'Honeypot_Used'}, 'VariableTypes', {'double','double', 'char', 'double', 'double', 'double', 'double', 'double', 'double', 'double', 'double', 'logical'});

figure;
scatter(nodePositions(:,1), nodePositions(:,2), 'filled');
title('WSN Topology');
xlabel('X-axis');
ylabel('Y-axis');
axis equal;

energyThreshold = 0.5;  
transmissionCountThreshold = 20; 
ipsTransmissionRange = 25;  
honeypotRange = 40;  
energyIncreaseFactor = 1.5; 


for entryIndex = 1:numEntries
    attackNode = randi(numNodes);
    attackType = 'Sinkhole';  
    
    nodePositions = updateNodePositions(nodePositions, nodeMobility);
    
    energyLevels = initializeEnergyLevels(numNodes, initialEnergy);

    attackDuration = randi([10, 50]);
    
    transmissionCount = zeros(1, numNodes);  % Track the number of transmissions
    
    for t = 1:simulationDuration
        disp(['Entry ' num2str(entryIndex) ', Attack Type: ' attackType ', Time Step ' num2str(t)]);
        
        % IPS detection logic
        detectedAbnormalEnergy = detectAbnormalEnergy(energyLevels, energyThreshold);
        detectedAbnormalTransmission = detectAbnormalTransmission(transmissionCount, transmissionCountThreshold);
        bypassIPS = true;

        if detectedAbnormalEnergy || detectedAbnormalTransmission
            disp('Abnormal behavior detected by IPS. Applying preventive measures.');
            
            honeypotUsed = useHoneypot(attackNode, nodePositions, honeypotRange);
            if honeypotUsed
                disp('Honeypot used to lure the attacker.');
                ipsTransmissionRange = calculateIPSTransmissionRange(energyLevels, energyThreshold);
                transmissionRange = min(transmissionRange, ipsTransmissionRange);
            end
            
            % Apply IPS to reduce transmission range based on abnormal energy consumption
            ipsTransmissionRange = calculateIPSTransmissionRange(energyLevels, energyThreshold);
            transmissionRange = min(transmissionRange, ipsTransmissionRange);
            
            % Allow for some attacks to bypass IPS prevention
            if bypassOne(energyLevels, transmissionCount, transmissionCountThreshold)
                transmissionRange = 30; 
            end
        else
            transmissionRange = 30;  % Reset transmission range
        end
        
        if t <= attackDuration
            for i = 1:numNodes
                if i == attackNode
                    continue;
                end
                
                if isNodeInRange(nodePositions, i, attackNode, transmissionRange)
                    disp(['Node ' num2str(i) ' transmitted data.']);
                    
                    % IPS prevention logic
                    preventedSinkhole = preventSinkholeAttack(i, nodePositions, attackNode, transmissionRange, energyLevels, energyThreshold);

                    if preventedSinkhole && bypassTwo(energyLevels, transmissionCount, transmissionCountThreshold)
                        disp(['IPS prevented Sinkhole attack from Node ' num2str(i) '.']);
                        % Collect data only for Sinkhole attack
                        newRow = createSimulationRow(entryIndex,i, attackType, t, initialEnergy, energyLevels(i), 0, 0, 0, attackDuration, 1, honeypotUsed);

                        sinkholeResults = [sinkholeResults; newRow];
                        continue;  % Skip this transmission as it's prevented by IPS
                    end
                    
                    [energyConsumed, energyDrained] = simulateSinkholeEnergyConsumption(initialEnergy, energyLevels(i), transmissionRange, distance(nodePositions(i,:), nodePositions(attackNode,:)), 0);
                    energyLevels(i) = energyLevels(i) - energyConsumed;
                    
                    actualAttackSuccessRate = calculateActualAttackSuccessRate(attackType, energyConsumed);
                    honeypotUsed = useHoneypot(attackNode, nodePositions, honeypotRange);

                    % Collect data only for Sinkhole attack
                    newRow = createSimulationRow(entryIndex, i, attackType, t, initialEnergy, energyLevels(i), energyDrained, energyConsumed, actualAttackSuccessRate, attackDuration, 0, honeypotUsed);
                    sinkholeResults = [sinkholeResults; newRow];
                    
                    % Update transmission count for IPS
                    transmissionCount(i) = transmissionCount(i) + 1;
                end
            end
        end
        
        energyLevels = updateEnergyLevels(energyLevels, calculateIdleEnergyConsumption(energyLevels) * energyIncreaseFactor);
    end
end


% Save the Sinkhole attack simulation results
saveSimulationResults(sinkholeResults, 'sinkhole_attack_simulation_results.csv');
calculateAndSaveMetrics(sinkholeResults, numEntries, 'simulation_metrics.csv');

function calculateAndSaveMetrics(simulationResults, numEntries, filename)
    % Initialize variables to store overall metrics
    totalTransmittedPackets = 0;
    totalReceivedPackets = 0;
    totalEnergyConsumption = 0;
    totalDelay = 0;

    % Loop through each entry
    for entryIndex = 1:numEntries
        % Calculate metrics for the current entry
        entryMetrics = calculateEntryMetrics(simulationResults, entryIndex);

        % Accumulate overall metrics
        totalTransmittedPackets = totalTransmittedPackets + entryMetrics.TransmittedPackets;
        totalReceivedPackets = totalReceivedPackets + entryMetrics.ReceivedPackets;
        totalEnergyConsumption = totalEnergyConsumption + entryMetrics.EnergyConsumption;
        totalDelay = totalDelay + entryMetrics.AvgDelay;
    end

    % Calculate overall metrics
    overallMetrics = calculateOverallMetrics(numEntries, totalTransmittedPackets, totalReceivedPackets, totalEnergyConsumption, totalDelay);

    % Save the metrics to a CSV file
    writetable(overallMetrics, filename);
end
function entryMetrics = calculateEntryMetrics(simulationResults, entryIndex)
    % Filter simulationResults for the current entry
    entryResults = simulationResults(simulationResults.EntryIndex == entryIndex, :);

    % Calculate metrics for the current entry
    entryMetrics.TransmittedPackets = height(entryResults);
    entryMetrics.ReceivedPackets = sum(entryResults.ActualAttackSuccessRate > 0);
    entryMetrics.EnergyConsumption = sum(entryResults.ActualEnergyConsumed);
    entryMetrics.AvgDelay = mean(entryResults.TimeStep);
end

function overallMetrics = calculateOverallMetrics(numEntries, totalTransmittedPackets, totalReceivedPackets, totalEnergyConsumption, totalDelay)
    % Calculate aggregated metrics for the entire simulation
    overallMetrics.Throughput = totalReceivedPackets / numEntries;
    overallMetrics.PacketDeliveryRatio = totalReceivedPackets / totalTransmittedPackets;
    overallMetrics.AvgEnergyConsumption = totalEnergyConsumption / totalTransmittedPackets;
    overallMetrics.AvgDelay = totalDelay / totalTransmittedPackets;

    % Create a table to store the metrics
    overallMetrics = struct2table(overallMetrics);
end
%Bypass conditions
function result = bypassOne(energyLevels, transmissionCount, transmissionCountThreshold)
    % Check if a certain percentage of nodes are exhibiting abnormal behavior
    abnormalNodePercentage = sum(energyLevels > (mean(energyLevels) * (1 + energyThreshold))) / numNodes;
    
    % Check if the overall transmission count exceeds a threshold
    highTransmissionCount = any(transmissionCount > transmissionCountThreshold);
    
    % IPS bypass condition: If abnormal nodes are less than 10% and transmission count is not high
    result = abnormalNodePercentage < 0.1 && ~highTransmissionCount;
end

% Function to represent realistic condition for partial IPS prevention
function result =  bypassTwo(energyLevels, transmissionCount, transmissionCountThreshold)
    % Check if there is a sudden spike in energy consumption for any node
    suddenSpike = any(diff(energyLevels) > 100);  % Adjust the threshold as needed
    
    % IPS partial prevention condition: If there is a sudden spike in energy consumption
    result = suddenSpike;
end

function honeypotUsed = useHoneypot(attackNode, nodePositions, honeypotRange)
    % Your logic to determine if honeypot is used
    % For example, check if any node is within honeypotRange of the attackNode
    honeypotUsed = any(distance(nodePositions(attackNode,:), nodePositions) <= honeypotRange);
end
function ipsTransmissionRange = calculateIPSTransmissionRange(energyLevels, energyThreshold)
    % Placeholder function, you can modify this based on your IPS logic
     % Set IPS transmission range as needed
    abnormalNodes = energyLevels > (mean(energyLevels) * (1 + energyThreshold));
    if any(abnormalNodes)
        reductionFactor = 0.8;  % You can adjust this factor as needed
        ipsTransmissionRange = min(energyLevels(~abnormalNodes)) * reductionFactor;
    else
        ipsTransmissionRange = Inf;  % No abnormal nodes, set to infinity
    end
end

function detectedAbnormalEnergy = detectAbnormalEnergy(energyLevels, energyThreshold)
    % IPS logic: Detect abnormal energy consumption
    detectedAbnormalEnergy = any(energyLevels > (mean(energyLevels) * (1 + energyThreshold)));
end

function detectedAbnormalTransmission = detectAbnormalTransmission(transmissionCount, transmissionCountThreshold)
    % IPS logic: Detect abnormal transmission count
    detectedAbnormalTransmission = any(transmissionCount > transmissionCountThreshold);
end

function detectedSinkhole = detectSinkholeAttack(energyLevels, transmissionCount, energyThreshold, transmissionCountThreshold)
    % IDS logic: Detect Sinkhole based on abnormal energy consumption and transmission count
    averageEnergyConsumption = mean(energyLevels);
    energyConsumptionThreshold = averageEnergyConsumption * (1 + energyThreshold);
    
    % Check if any node has abnormal energy consumption or transmission count
    detectedSinkhole = any(energyLevels > energyConsumptionThreshold) || any(transmissionCount > transmissionCountThreshold);
end

function preventedSinkhole = preventSinkholeAttack(node, nodePositions, attackNode, transmissionRange, energyLevels, energyThreshold)
    % IPS logic: Prevent Sinkhole by checking if the attacker is in range
        preventedSinkhole = isNodeInRange(nodePositions, node, attackNode, transmissionRange) && (energyLevels(node) > energyThreshold);
 
end

% The rest of the functions remain unchanged.


function [energyConsumed, energyDrained] = simulateSinkholeEnergyConsumption(initialEnergy, currentEnergy, transmissionRange, distanceToAttackNode, packetsIntercepted)
    transmissionLoss = exp(-distanceToAttackNode / transmissionRange);
    
    % Customize the energy consumption for Sinkhole attack
    interceptedFactor = 1 + 0.1 * packetsIntercepted; % Adjust the factor based on intercepted packets
    energyConsumed = min(currentEnergy, initialEnergy * (1 - transmissionLoss) * interceptedFactor) * 0.9;  % Default factor for Sinkhole
    energyDrained = currentEnergy - (currentEnergy - energyConsumed);
end


function idleEnergyConsumption = calculateIdleEnergyConsumption(energyLevels)
    idleEnergyConsumption = mean(energyLevels) * 0.002;
end

function actualAttackSuccessRate = calculateActualAttackSuccessRate(attackType, energyConsumed)
    actualAttackSuccessRate = 1 - exp(-energyConsumed / 100);
end


function inRange = isNodeInRange(nodePositions, node1, node2, range)
    inRange = distance(nodePositions(node1,:), nodePositions(node2,:)) <= range;
end

function updatedPositions = updateNodePositions(nodePositions, mobility)
    updatedPositions = nodePositions + mobility * randn(size(nodePositions));
end

function energyLevels = initializeEnergyLevels(numNodes, initialEnergy)
    energyLevels = ones(1, numNodes) * initialEnergy;
end

function updatedEnergyLevels = updateEnergyLevels(energyLevels, idleEnergyConsumption)
    updatedEnergyLevels = energyLevels - idleEnergyConsumption;
end

function newRow = createSimulationRow(entryIndex,node, attackType, timeStep, initialEnergy, energyLevel, energyDrained, energyConsumed, attackSuccessRate, attackDuration, ipsPrevented, honeypotUsed)
    newRow = {entryIndex,node, attackType, timeStep, initialEnergy, energyLevel, energyDrained, energyConsumed, attackSuccessRate, attackDuration, ipsPrevented, honeypotUsed};
end


function d = distance(p1, p2)
    d = sqrt(sum((p1 - p2).^2));
end

function saveSimulationResults(simulationResults, filename)
    randomFilename = fullfile(['simulation_results_' num2str(randi(1000)) '.csv']);
    writetable(simulationResults, randomFilename, 'WriteRowNames', false);
end
